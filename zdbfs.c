#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include "zdbfs.h"
#include "zdb.h"
#include "inode.h"

void zdbd_fulldump(void *_data, size_t len) {
    uint8_t *data = _data;
    unsigned int i, j;

    printf("[*] data fulldump [%p -> %p] (%lu bytes)\n", data, data + len, len);
    printf("[*] 0x0000: ");

    for(i = 0; i < len; ) {
        printf("%02x ", data[i++]);

        if(i % 16 == 0) {
            printf("|");

            for(j = i - 16; j < i; j++)
                printf("%c", ((isprint(data[j]) ? data[j] : '.')));

            printf("|\n[*] 0x%04x: ", i);
        }
    }

    if(i % 16) {
        printf("%-*s |", 5 * (16 - (i % 16)), " ");

        for(j = i - (i % 16); j < len; j++)
            printf("%c", ((isprint(data[j]) ? data[j] : '.')));

        printf("%-*s|\n", 16 - ((int) len % 16), " ");
    }

    printf("\n");
}


void dies(char *help, char *value) {
    fprintf(stderr, "[-] %s: %s\n", help, value);
    exit(EXIT_FAILURE);
}

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

static void hello_ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	struct stat stbuf;
	(void) fi;

    zdbfs_debug("[+] getattr: ino: %ld\n", ino);

	memset(&stbuf, 0, sizeof(stbuf));

    if(zdbfs_inode_stat(req, ino, &stbuf)) {
        fuse_reply_err(req, ENOENT);
        return; // FIXME
    }

    fuse_reply_attr(req, &stbuf, 1.0);
}

static void zdbfs_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
	struct fuse_entry_param e;

    zdbfs_debug("[+] lookup: parent: %ld, name: %s\n", parent, name);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, parent)))
        return;

    // fillin direntry with inode contents
    zdbfs_debug("[+] lookup: %lu: okay, looking for entry: %s\n", parent, name);
    zdb_dir_t *dir = inode->extend[0];

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        if(strcmp(entry->name, name) == 0) {
            memset(&e, 0, sizeof(e));

            if(zdbfs_inode_stat(req, entry->ino, &e.attr)) {
                fuse_reply_err(req, ENOENT);
                return; // FIXME
            }

            e.ino = entry->ino;
            e.attr_timeout = 10.0;
            e.entry_timeout = 10.0;

            fuse_reply_entry(req, &e);

            // FIXME
            return;
        }
    }

    fuse_reply_err(req, ENOENT);
}

static void zdbfs_fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
	struct fuse_entry_param e;
    zdbfs_t *fs = fuse_req_userdata(req);
    uint32_t ino;

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, parent)))
        return;

    // new file
    zdb_inode_t *create = zdbfs_inode_new_file(req, 0644);
    buffer_t newfile = zdbfs_inode_serialize(create);

    if((ino = zdb_set(fs->mdctx, 0, newfile.buffer, newfile.length)) == 0)
        dies("create", "could not create inode");

    zdbfs_inode_dump(inode);

    // update directory with new entry
    zdb_dir_t *dir = inode->extend[0];
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(ino, name));
    inode->extend[0] = dir;

    buffer_t save = zdbfs_inode_serialize(inode);

    if(zdb_set(fs->mdctx, parent, save.buffer, save.length) != parent)
        dies("create", "could not update parent directory");

    memset(&e, 0, sizeof(e));
    e.ino = ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    zdbfs_inode_to_stat(&e.attr, create);
    free(create->extend[0]);
    free(create);

    fuse_reply_create(req, &e, fi);
}

struct dirbuf {
	char *p;
	size_t size;
};

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off, min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

static void zdbfs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
	struct fuse_entry_param e;
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    zdbfs_t *fs = fuse_req_userdata(req);

    zdbfs_debug("[+] mkdir: parent: %ld, name: %s\n", parent, name);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, parent)))
        return;

    // create new empty dir, sending it to the backend
    zdb_inode_t *newdir = zdbfs_mkdir_empty(parent, mode);
    newdir->uid = ctx->uid;
    newdir->gid = ctx->gid;

    buffer_t xnewdir = zdbfs_inode_serialize(newdir);

    uint32_t ino;
    if((ino = zdb_set(fs->mdctx, 0, xnewdir.buffer, xnewdir.length)) == 0)
        dies("mkdir", "could not create new directory");

    zdb_dir_t *dir = inode->extend[0];
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(ino, name));

    buffer_t xparent = zdbfs_inode_serialize(inode);
    if(zdb_set(fs->mdctx, parent, xparent.buffer, xparent.length) != parent)
        dies("mkdir", "could not update parent directory");

    memset(&e, 0, sizeof(e));
    e.ino = ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    zdbfs_inode_to_stat(&e.attr, newdir);

    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
	(void) fi;

    zdbfs_debug("[+] readdir: %lu: request\n", ino);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, ino)))
        return;

    // fillin direntry with inode contents
    zdbfs_debug("[+] readdir: %lu: okay, fillin entries\n", ino);
    zdb_dir_t *dir = inode->extend[0];

    struct dirbuf bb, *b;
    b = &bb;
	memset(b, 0, sizeof(bb));

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        struct stat stbuf;
        size_t oldsize = b->size;

        // FIXME
        b->size += fuse_add_direntry(req, NULL, 0, entry->name, NULL, 0);
        b->p = (char *) realloc(b->p, b->size);
        memset(&stbuf, 0, sizeof(stbuf));
        stbuf.st_ino = entry->ino;
        fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, entry->name, &stbuf, b->size);
    }

	reply_buf_limited(req, bb.p, bb.size, off, size);
	free(bb.p);
}



static void zdbfs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    zdb_inode_t *inode;

    zdbfs_debug("[+] open: ino %lu: request\n", ino);

    if(!(inode = zdbfs_fetch_inode(req, ino)))
        return;

    if(S_ISDIR(inode->mode)) {
		fuse_reply_err(req, EISDIR);
        return;
    }

    /*
	if((fi->flags & O_ACCMODE) != O_RDONLY) {
		fuse_reply_err(req, EACCES);
        return;
    }
    */

    fuse_reply_open(req, fi);
}

static void zdbfs_fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
	(void) fi;
    zdbfs_t *fs = fuse_req_userdata(req);
    zdbfs_debug("[+] read: ino %lu: size %lu, off: %lu\n", ino, size, off);

    if(off != 0) {
        printf("offset zero needed\n");
        fuse_reply_err(req, EIO);
        return;
    }

    if(size > BLOCK_SIZE) {
        printf("size too large\n");
        fuse_reply_err(req, EIO);
        return;
    }

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_inode(req, ino))) {
        printf("cannot fetch inode\n");
        fuse_reply_err(req, EIO);
        return;
    }

    uint32_t blockid = zdbfs_offset_to_block(off);
    zdb_blocks_t *blocks = inode->extend[0];

    zdbfs_inode_dump(inode);
    printf(">> BLOCK ID: %u\n", blocks->blocks[blockid]);

    zdb_reply_t *reply;
    if(!(reply = zdb_get(fs->datactx, blocks->blocks[blockid]))) {
        printf("could not find inode\n");
        fuse_reply_err(req, EIO);
        return;
    }

	reply_buf_limited(req, (const char *) reply->value, reply->length, off, size);
}
static void zdbfs_fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_debug("[+] write: ino %lu: size %lu, off: %lu\n", ino, size, off);
    zdbfs_t *fs = fuse_req_userdata(req);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_inode(req, ino))) {
        fuse_reply_write(req, 0);
        return;
    }

    if(off != 0) {
        printf("offset zero needed\n");
        fuse_reply_write(req, 0);
        return;
    }

    if(size > BLOCK_SIZE) {
        printf("too large for now\n");
        fuse_reply_write(req, 0);
    }

    //
    // assume linear write for now
    //

    size_t block = zdbfs_offset_to_block(off);
    uint32_t blockid;

    if((blockid = zdb_set(fs->datactx, 0, buf, size)) == 0)
        dies("write", "cannot write block to backend");

    // FIXME
    inode->size = size;

    zdbfs_inode_set_block(inode, block, blockid);

    buffer_t newinfo = zdbfs_inode_serialize(inode);
    if(zdb_set(fs->mdctx, ino, newinfo.buffer, newinfo.length) != ino)
        dies("mkdir", "could not update inode blocks");

    fuse_reply_write(req, size);
}

static const struct fuse_lowlevel_ops hello_ll_oper = {
	.lookup		= zdbfs_fuse_lookup,
	.getattr	= hello_ll_getattr,
	.readdir	= zdbfs_fuse_readdir,
	.open		= zdbfs_fuse_open,
	.read		= zdbfs_fuse_read,
    .write      = zdbfs_fuse_write,
    .mkdir      = zdbfs_fuse_mkdir,
    .create     = zdbfs_fuse_create,
};

int main(int argc, char *argv[]) {
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	struct fuse_loop_config config;
    zdbfs_t zdbfs = {
        .mdctx = NULL,
        .datactx = NULL,
    };



    printf("[+] initializing zdb filesystem\n");
    zdbfs_zdb_connect(&zdbfs);
    zdbfs_create(&zdbfs);


	if(fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if(opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		fuse_cmdline_help();
		fuse_lowlevel_help();
        return 0;

	} else if(opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
        return 0;
	}

	if(opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
        return 1;
	}

    printf("[+] initializing fuse session\n");
	if(!(se = fuse_session_new(&args, &hello_ll_oper, sizeof(hello_ll_oper), &zdbfs)))
        return 1;

    printf("[+] initializing signals\n");
	if(fuse_set_signal_handlers(se) != 0)
        return 1;

    printf("[+] mounting session\n");
	if(fuse_session_mount(se, opts.mountpoint) != 0)
        return 1;

	// fuse_daemonize(opts.foreground);
	// fuse_daemonize(0);

	// if(opts.singlethread)
    printf("[+] processing events\n");
	int ret = fuse_session_loop(se);

    /*
	else {
		config.clone_fd = opts.clone_fd;
		config.max_idle_threads = opts.max_idle_threads;
		ret = fuse_session_loop_mt(se, &config);
	}
    */

    printf("\n[+] cleaning environment\n");
	fuse_session_unmount(se);
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);

	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret;
}
