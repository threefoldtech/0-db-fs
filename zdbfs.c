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
#include <errno.h>
#include "zdbfs.h"
#include "zdb.h"
#include "inode.h"

//
// debug purpose
//
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

//
// general helpers
//
void dies(char *help, char *value) {
    fprintf(stderr, "[-] %s: %s\n", help, value);
    exit(EXIT_FAILURE);
}

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

// propagate an error to fuse with verbosity
#define zdbfs_fuse_error(req, err, ino) zdbfs_fuse_error_caller(req, err, ino, __func__)

void zdbfs_fuse_error_caller(fuse_req_t req, int err, uint32_t ino, const char *caller) {
    zdbfs_debug("[-] %s: ino %u: %s\n", caller, ino, strerror(err));
    fuse_reply_err(req, err);
}



//
// fuse syscall implementation
//
static void zdbfs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    struct stat stbuf;
    (void) fi;

    zdbfs_debug("[+] syscall: getattr: ino: %ld\n", ino);

    if(zdbfs_inode_stat(req, ino, &stbuf))
        return zdbfs_fuse_error(req, ENOENT, ino);

    fuse_reply_attr(req, &stbuf, 1.0);
}

void zdbfs_fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    struct stat stbuf;
    zdb_inode_t *inode;
    (void) fi;

    zdbfs_debug("[+] syscall: setattr: ino: %ld\n", ino);

    // fetching current inode state
    if(!(inode = zdbfs_fetch_inode(req, ino)))
        zdbfs_fuse_error(req, ENOENT, ino);

    memset(&stbuf, 0, sizeof(stbuf));

    // update inode based on request
    if(to_set & FUSE_SET_ATTR_MODE)
        inode->mode = attr->st_mode;

    if(to_set & FUSE_SET_ATTR_UID)
        inode->uid = attr->st_uid;

    if(to_set & FUSE_SET_ATTR_GID)
        inode->gid = attr->st_gid;

    if(to_set & FUSE_SET_ATTR_SIZE)
        inode->size = attr->st_size;

    if(to_set & FUSE_SET_ATTR_ATIME)
        inode->atime = attr->st_atim.tv_sec;

    if(to_set & FUSE_SET_ATTR_MTIME)
        inode->mtime = attr->st_mtim.tv_sec;

    if(to_set & FUSE_SET_ATTR_ATIME_NOW)
        inode->atime = time(NULL);

    if(to_set & FUSE_SET_ATTR_MTIME_NOW)
        inode->mtime = time(NULL);

    if(to_set & FUSE_SET_ATTR_CTIME)
        inode->ctime = attr->st_ctim.tv_sec;

    // save updated inode to backend
    if(zdbfs_inode_store(fs->mdctx, inode, ino) != ino) {
        zdbfs_fuse_error(req, EIO, ino);
        goto cleanup;
    }

    // send updated information back to caller
    zdbfs_inode_to_stat(&stbuf, inode);
    fuse_reply_attr(req, &stbuf, 1.0);

cleanup:
    zdbfs_inode_free(inode);
}

static void zdbfs_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    struct fuse_entry_param e;
    int found = 0;

    zdbfs_debug("[+] syscall: lookup: parent: %ld, name: %s\n", parent, name);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, parent)))
        return;

    // fillin direntry with inode contents
    zdbfs_debug("[+] lookup: %lu: okay, looking for entry: %s\n", parent, name);
    zdb_dir_t *dir = inode->extend[0];
    memset(&e, 0, sizeof(e));

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        if(strcmp(entry->name, name) == 0) {

            if(zdbfs_inode_stat(req, entry->ino, &e.attr))
                break;

            e.ino = entry->ino;
            e.attr_timeout = 10.0;
            e.entry_timeout = 10.0;

            fuse_reply_entry(req, &e);
            found = 1;

            break;
        }
    }

    if(!found)
        zdbfs_fuse_error(req, ENOENT, parent);

    zdbfs_inode_free(inode);
}

static void zdbfs_fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
    struct fuse_entry_param e;
    zdbfs_t *fs = fuse_req_userdata(req);
    uint32_t ino;

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, parent)))
        return;

    // new file
    zdb_inode_t *create = zdbfs_inode_new_file(req, mode);
    if((ino = zdbfs_inode_store(fs->mdctx, create, 0)) == 0)
        dies("create", "could not create inode");

    // update directory with new entry
    zdb_dir_t *dir = inode->extend[0];
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(ino, name));
    inode->extend[0] = dir;

    if(zdbfs_inode_store(fs->mdctx, inode, parent) != parent)
        dies("create", "could not update parent directory");

    memset(&e, 0, sizeof(e));
    e.ino = ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    zdbfs_inode_to_stat(&e.attr, create);
    zdbfs_inode_free(create);
    zdbfs_inode_free(inode);

    fuse_reply_create(req, &e, fi);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize)
{
    // FIXME
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off, min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

static void zdbfs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    struct fuse_entry_param e;
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    zdbfs_t *fs = fuse_req_userdata(req);

    zdbfs_debug("[+] syscall: mkdir: parent: %ld, name: %s\n", parent, name);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, parent)))
        return;

    // create new empty dir, sending it to the backend
    zdb_inode_t *newdir = zdbfs_mkdir_empty(parent, mode);
    newdir->uid = ctx->uid;
    newdir->gid = ctx->gid;

    uint32_t ino;
    if((ino = zdbfs_inode_store(fs->mdctx, newdir, 0)) == 0) {
        zdbfs_fuse_error(req, EIO, 0);
        // FREE
        return;
    }

    /*
    buffer_t xnewdir = zdbfs_inode_serialize(newdir);

    if((ino = zdb_set(fs->mdctx, 0, xnewdir.buffer, xnewdir.length)) == 0)
        dies("mkdir", "could not create new directory");
    */

    zdb_dir_t *dir = inode->extend[0];
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(ino, name));
    inode->extend[0] = dir;

    if(zdbfs_inode_store(fs->mdctx, inode, parent) != parent) {
        printf("could not update parent\n");
        zdbfs_fuse_error(req, EIO, parent);
        // FREE
        return;
    }

    memset(&e, 0, sizeof(e));
    e.ino = ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    zdbfs_inode_to_stat(&e.attr, newdir);
    zdbfs_inode_free(newdir);
    zdbfs_inode_free(inode);

    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;

    zdbfs_debug("[+] syscall: readdir: %lu: request\n", ino);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_directory(req, ino)))
        return;

    // fillin direntry with inode contents
    zdbfs_debug("[+] readdir: %lu: okay, fillin entries\n", ino);
    zdb_dir_t *dir = inode->extend[0];

    buffer_t buffer;
    buffer.length = 0;

    // first pass: computing total size
    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        buffer.length += fuse_add_direntry(req, NULL, 0, entry->name, NULL, 0);
    }

    // allocate buffer large enough
    if(!(buffer.buffer = calloc(buffer.length, 1)))
        diep("readdir: calloc");

    // fill in the buffer for each entries
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    uint8_t *ptr = buffer.buffer;

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        size_t cursize = fuse_add_direntry(req, NULL, 0, entry->name, NULL, 0);
        off_t eoff = (off_t) ptr + cursize;

        stbuf.st_ino = entry->ino;
        fuse_add_direntry(req, (char *) ptr, cursize, entry->name, &stbuf, eoff);

        ptr += cursize;
    }

    // FIXME
    reply_buf_limited(req, buffer.buffer, buffer.length, off, size);

    free(buffer.buffer);
    zdbfs_inode_free(inode);
}

static void zdbfs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    zdb_inode_t *inode;
    int ok = 1;

    zdbfs_debug("[+] syscall: open: ino %lu: request\n", ino);

    if(!(inode = zdbfs_fetch_inode(req, ino)))
        return;

    if(S_ISDIR(inode->mode)) {
        zdbfs_fuse_error(req, EISDIR, ino);
        ok = 0;
    }

    zdbfs_inode_free(inode);

    /*
    if((fi->flags & O_ACCMODE) != O_RDONLY) {
        fuse_reply_err(req, EACCES);
        return;
    }
    */

    if(ok)
        fuse_reply_open(req, fi);
}

static void zdbfs_fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_t *fs = fuse_req_userdata(req);
    size_t fetched = 0;
    char *buffer;

    zdbfs_debug("[+] syscall: read: ino %lu: size %lu, off: %lu\n", ino, size, off);

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_inode(req, ino)))
        zdbfs_fuse_error(req, EIO, ino);

    // zdbfs_inode_dump(inode);

    zdb_blocks_t *blocks = inode->extend[0];

    if(!(buffer = malloc(size)))
        diep("read: malloc buffer");

    // for each block to send
    while(fetched < size) {
        uint32_t block = zdbfs_offset_to_block(off);

        if(block >= blocks->length) {
            zdbfs_debug("[+] read: block ouf of bounds, eof reached\n");
            fetched = 0;
            break;
        }

        uint32_t blockid = blocks->blocks[block];
        zdbfs_debug("[+] read: fetching block: %u [%u]\n", block, blockid);

        zdb_reply_t *reply;
        if(!(reply = zdb_get(fs->datactx, blockid))) {
            printf("could not find block\n");
            zdbfs_fuse_error(req, EIO, ino);
            free(buffer);
            return;
        }

        // fetched block contains something we need
        // the full block can be used, or partial content
        // partial content can be anywhere and any length inside
        // the block

        // checking if request is aligned with our block
        size_t alignment = (off % BLOCK_SIZE);

        // computing remaining size to fetch
        size_t remain = size - fetched;

        // checking if the whole block can be used or not
        size_t chunk = (remain <= reply->length - alignment) ? remain : reply->length - alignment;

        zdbfs_debug("[+] read: copying %lu bytes (block align: %lu)\n", chunk, alignment);
        memcpy(buffer + fetched, reply->value + alignment, chunk);

        // cleaning block read
        zdb_free(reply);

        fetched += chunk;
        off += chunk;
    }

    fuse_reply_buf(req, buffer, fetched);

    free(buffer);
    zdbfs_inode_free(inode);
}

static void zdbfs_fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_debug("[+] syscall: write: ino %lu: size %lu, off: %lu\n", ino, size, off);
    zdbfs_t *fs = fuse_req_userdata(req);
    size_t sent = 0;

    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_inode(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    // zdb_blocks_t *blocks = inode->extend[0];

    // sending each blocks
    while(sent < size) {
        size_t block = zdbfs_offset_to_block(off + sent);
        uint32_t blockid;
        size_t towrite = (size > BLOCK_SIZE) ? BLOCK_SIZE : size;
        zdbfs_debug("[+] write: writing %lu bytes (sent %lu / %lu)\n", towrite, sent, size);

        if((blockid = zdb_set(fs->datactx, 0, buf + sent, towrite)) == 0) {
            dies("write", "cannot write block to backend");
        }

        zdbfs_inode_set_block(inode, block, blockid);

        sent += towrite;
        inode->size += towrite; // FIXME: does not support overwrite
    }

    if(zdbfs_inode_store(fs->mdctx, inode, ino) == 0) {
        dies("write", "could not update inode blocks");
    }

    fuse_reply_write(req, sent);
    zdbfs_inode_free(inode);
}

void zdbfs_fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    /*
    zdb_inode_t *inode;
    if(!(inode = zdbfs_fetch_inode(req, parent))) {
        printf("could not fetch inode\n");
        fuse_reply_err(req, ENOENT);
        return;
    }
    */

    zdbfs_fuse_error(req, ENOENT);
}

static const struct fuse_lowlevel_ops hello_ll_oper = {
    .lookup     = zdbfs_fuse_lookup,
    .getattr    = zdbfs_fuse_getattr,
    .setattr    = zdbfs_fuse_setattr,
    .readdir    = zdbfs_fuse_readdir,
    .open       = zdbfs_fuse_open,
    .read       = zdbfs_fuse_read,
    .write      = zdbfs_fuse_write,
    .mkdir      = zdbfs_fuse_mkdir,
    .create     = zdbfs_fuse_create,
    .unlink     = zdbfs_fuse_unlink,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    // struct fuse_loop_config config;

    zdbfs_t zdbfs = {
        .mdctx = NULL,
        .datactx = NULL,
    };



    printf("[+] initializing zdb filesystem\n");
    zdbfs_zdb_connect(&zdbfs);
    zdbfs_initialize_filesystem(&zdbfs);


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

    zdbfs_debug("[+] fuse: initializing session\n");
    if(!(se = fuse_session_new(&args, &hello_ll_oper, sizeof(hello_ll_oper), &zdbfs)))
        return 1;

    zdbfs_debug("[+] fuse: initializing signals\n");
    if(fuse_set_signal_handlers(se) != 0)
        return 1;

    zdbfs_debug("[+] fuse: mounting session\n");
    if(fuse_session_mount(se, opts.mountpoint) != 0)
        return 1;

    // fuse_daemonize(opts.foreground);
    // fuse_daemonize(0);

    // if(opts.singlethread)
    zdbfs_debug("[+] fuse: ready, waiting events\n");
    int ret = fuse_session_loop(se);

    /*
    else {
        config.clone_fd = opts.clone_fd;
        config.max_idle_threads = opts.max_idle_threads;
        ret = fuse_session_loop_mt(se, &config);
    }
    */

    zdbfs_debug("\n[+] fuse: cleaning environment\n");
    fuse_session_unmount(se);
    fuse_remove_signal_handlers(se);
    fuse_session_destroy(se);

    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    // disconnect redis
    redisFree(zdbfs.mdctx);
    redisFree(zdbfs.datactx);

    return ret;
}
