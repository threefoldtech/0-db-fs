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

#define zdbfs_debug printf

#define BLOCK_SIZE  4096

typedef struct zdbfs_t {
    redisContext *mdctx;
    redisContext *datactx;

} zdbfs_t;

typedef struct zdb_blocks_t {
    uint64_t length;
    uint32_t blocks[];

} __attribute__((packed)) zdb_blocks_t;

typedef struct zdb_direntry_t {
    uint16_t size;
    uint32_t ino;
    char name[];

} __attribute__((packed)) zdb_direntry_t;

typedef struct zdb_dir_t {
    uint32_t length;
    zdb_direntry_t *entries[];

} __attribute__((packed)) zdb_dir_t;

typedef struct zdb_inode_t {
    uint32_t mode;
    uint32_t ino;
    uint32_t dev;
    uint16_t uid;
    uint16_t gid;
    uint64_t size;
    uint32_t atime;
    uint32_t mtime;
    uint32_t ctime;
    void *extend[];

} __attribute__((packed)) zdb_inode_t;



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

static void zdbfs_inode_dump(zdb_inode_t *inode) {
    printf("[+] --- inode dump\n");
    printf("[+] mode: %x\n", inode->mode);
    printf("[+] is directory: %s\n", S_ISDIR(inode->mode) ? "yes" : "no");

    if(S_ISDIR(inode->mode)) {
        zdb_dir_t *dir = inode->extend[0];
        printf("[+] directory length: %u\n", dir->length);

        for(size_t i = 0; i < dir->length; i++) {
            zdb_direntry_t *entry = dir->entries[i];
            printf("[+] directory content: %s [%u]\n", entry->name, entry->ino);
        }
    }

    if(S_ISREG(inode->mode)) {
        zdb_blocks_t *blocks = inode->extend[0];
        printf("[+] blocks length: %lu\n", blocks->length);

        for(size_t i = 0; i < blocks->length; i++)
            printf("[+] inode block id: %u\n", blocks->blocks[i]);
    }

    printf("[+] --- inode dump\n");
}


void dies(char *help, char *value) {
    fprintf(stderr, "[-] %s: %s\n", help, value);
    exit(EXIT_FAILURE);
}

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}



int zdbfs_zdb_connect(zdbfs_t *fs) {
    printf("[+] connecting metadata zdb\n");

    if(!(fs->mdctx = redisConnect("127.0.0.1", 9900)))
        diep("redis init");

    if(fs->mdctx->err) {
        fprintf(stderr, "[-] redis: %s\n", fs->mdctx->errstr);
        return 1;
    }

    printf("[+] connecting data zdb\n");
    if(!(fs->datactx = redisConnect("127.0.0.1", 9900)))
        diep("redis init");

    if(fs->datactx->err) {
        fprintf(stderr, "[-] redis: %s\n", fs->datactx->errstr);
        return 1;
    }

    redisReply *reply;

    if(!(reply = redisCommand(fs->mdctx, "SELECT metadata")))
        diep("redis select metadata");

    if(strcmp(reply->str, "OK") != 0)
        dies("metadata namespacd", reply->str);

    freeReplyObject(reply);

    if(!(reply = redisCommand(fs->datactx, "SELECT fsdata")))
        diep("redis select data");

    if(strcmp(reply->str, "OK") != 0)
        dies("data namespacd", reply->str);

    freeReplyObject(reply);

    return 0;
}

typedef struct buffer_t {
    void *buffer;
    size_t length;

} buffer_t;

typedef struct zdb_reply_t {
    redisReply *rreply;
    uint8_t *value;
    size_t length;

} zdb_reply_t;

static zdb_reply_t *zdb_get(redisContext *remote, uint32_t id) {
    zdb_reply_t *reply;

    zdbfs_debug("[+] get: zdb: request inode: %u\n", id);

    if(!(reply = calloc(sizeof(zdb_reply_t), 1)))
        diep("reply: malloc");

    if(!(reply->rreply = redisCommand(remote, "GET %b", &id, sizeof(id))))
        diep("redis: get");

    if(reply->rreply->type == REDIS_REPLY_NIL) {
        printf("[+] get: redis reply: nil\n");
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    reply->value = (uint8_t *) reply->rreply->str;
    reply->length = reply->rreply->len;

    return reply;
}

static uint32_t zdb_set(redisContext *remote, uint32_t id, const void *buffer, size_t length) {
    redisReply *reply;
    uint32_t response = 0;
    uint32_t *rid = &id;
    size_t rsize = sizeof(id);

    zdbfs_debug("[+] set: zdb: request inode: %u\n", id);

    // create new entry
    if(id == 0) {
        rsize = 0;
        rid = NULL;
    }

    if(!(reply = redisCommand(remote, "SET %b %b", rid, rsize, buffer, length)))
        diep("redis: set");

    if(reply->type == REDIS_REPLY_ERROR) {
        printf("<< %s\n", reply->str);
        freeReplyObject(reply);
        return 0;
    }

    if(reply->type == REDIS_REPLY_NIL) {
        // if response is zero
        // this mean entry was not updated (no changes)
        // but it's a valid a reponse, not an error
        printf("[+] set: zdb: key already up-to-date\n");
        freeReplyObject(reply);
        return id;
    }

    if(reply->len == sizeof(id))
        memcpy(&response, reply->str, sizeof(id));

    freeReplyObject(reply);

    return response;
}

static void zdb_free(zdb_reply_t *reply) {
    freeReplyObject(reply->rreply);
    free(reply);
}




static struct timespec zdbfs_time_sys(uint32_t source) {
    struct timespec ts = {
        .tv_sec = source,
        .tv_nsec = 0,
    };

    return ts;
}



static size_t zdbfs_direntry_size(zdb_direntry_t *entry) {
    return sizeof(zdb_direntry_t) + entry->size + 1;
}

static zdb_direntry_t *zdbfs_direntry_new(uint32_t ino, const char *name) {
    zdb_direntry_t *entry;
    size_t namelen = strlen(name);

    if(!(entry = malloc(sizeof(zdb_direntry_t) + namelen + 1)))
        diep("direntry: malloc");

    entry->ino = ino;
    entry->size = namelen;
    strcpy(entry->name, name);

    return entry;
}

static zdb_dir_t *zdbfs_dir_append(zdb_dir_t *dir, zdb_direntry_t *entry) {
    dir->length += 1;
    size_t entlen = sizeof(zdb_direntry_t *) * dir->length;

    if(!(dir = realloc(dir, sizeof(zdb_dir_t) + entlen)))
        diep("dir append: realloc");

    dir->entries[dir->length - 1] = entry;

    return dir;
}

static size_t zdbfs_inode_dir_size(zdb_dir_t *dir) {
    size_t length = sizeof(zdb_inode_t);
    length += sizeof(zdb_dir_t);

    for(size_t i = 0; i < dir->length; i++)
        length += zdbfs_direntry_size(dir->entries[i]);

    return length;
}

static size_t zdbfs_inode_file_size(zdb_inode_t *inode) {
    size_t length = sizeof(zdb_inode_t);
    length += sizeof(zdb_blocks_t);

    zdb_blocks_t *blocks = inode->extend[0];
    length += blocks->length * BLOCK_SIZE;

    return length;
}

static zdb_dir_t *zdbfs_dir_new(uint32_t parent) {
    zdb_dir_t *dir;

    // initialize an empty directory in memory
    if(!(dir = malloc(sizeof(zdb_dir_t))))
        diep("dir: malloc");

    // fill it with the 2 default entries
    dir->length = 0;
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(parent, "."));
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(parent, ".."));
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(42, "coucou"));

    return dir;
}

static zdb_inode_t *zdbfs_mkdir_empty(uint32_t parent, uint32_t mode) {
    zdb_dir_t *dir;
    zdb_inode_t *inode;

    // create empty directory
    dir = zdbfs_dir_new(parent);

    // create empty inode
    if(!(inode = calloc(sizeof(zdb_inode_t) + sizeof(zdb_dir_t *), 1)))
        diep("mkdir: empty: calloc");

    // set inode and link directory to it
    inode->mode = S_IFDIR | mode;
    inode->ctime = time(NULL);
    inode->atime = inode->ctime;
    inode->mtime = inode->ctime;

    inode->extend[0] = dir;

    return inode;
}

static zdb_inode_t *zdbfs_inode_deserialize_dir(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    (void) length;
    zdb_dir_t *dir, *xdir;

    //
    // directory deserialize
    //
    dir = (zdb_dir_t *) (buffer + sizeof(zdb_inode_t));
    size_t dirlen = sizeof(zdb_dir_t) + (sizeof(zdb_direntry_t *) * dir->length);

    if(!(dir = malloc(dirlen)))
        diep("deserialize: malloc dir");

    // link this directory contents to inode
    inode->extend[0] = dir;
    xdir = (zdb_dir_t *) (buffer + sizeof(zdb_inode_t));
    dir->length = xdir->length;

    uint8_t *ptr = (uint8_t *) &xdir->entries[0];

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = (zdb_direntry_t *) ptr;
        size_t entlen = zdbfs_direntry_size(entry);

        dir->entries[i] = zdbfs_direntry_new(entry->ino, entry->name);
        ptr += entlen;
    }

    return inode;
}

static zdb_inode_t *zdbfs_inode_deserialize_file(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    zdb_blocks_t *blocks = (zdb_blocks_t *) (buffer + sizeof(zdb_inode_t));

    if(!(inode->extend[0] = malloc(length - sizeof(zdb_inode_t))))
        diep("malloc");

    memcpy(inode->extend[0], blocks, length - sizeof(zdb_inode_t));

    return inode;
}

static zdb_inode_t *zdbfs_inode_deserialize(uint8_t *buffer, size_t length) {
    zdb_inode_t *inode;

    if(length < sizeof(zdb_inode_t))
        dies("deserialize", "wrong size from db");

    if(!(inode = malloc(sizeof(zdb_inode_t) + sizeof(zdb_dir_t *))))
        diep("deserialize: malloc inode");

    // copy inode from buffer to inode, as it
    memcpy(inode, buffer, sizeof(zdb_inode_t));

    // nothing more to do if it's not a directory
    if(!S_ISDIR(inode->mode))
        return zdbfs_inode_deserialize_file(inode, buffer, length);

    return zdbfs_inode_deserialize_dir(inode, buffer, length);
}

static buffer_t zdbfs_inode_serialize_file(zdb_inode_t *inode) {
    buffer_t buffer;
    zdb_inode_t *serial;
    zdb_blocks_t *blocks = inode->extend[0];

    size_t blen = sizeof(zdb_blocks_t) + (blocks->length * sizeof(uint32_t));
    size_t inolen = sizeof(zdb_inode_t) + blen;

    if(!(serial = malloc(inolen)))
        diep("serialize: malloc");

    // FIXME debug
    memset(serial, 0x42, inolen);

    // first copy the inode data
    memcpy(serial, inode, sizeof(zdb_inode_t));

    // set blocks
    memcpy(&serial->extend[0], inode->extend[0], blen);

    // zdbd_fulldump(serial, inolen);

    buffer.buffer = serial;
    buffer.length = inolen;

    return buffer;
}

static buffer_t zdbfs_inode_serialize_dir(zdb_inode_t *inode) {
    buffer_t buffer;
    zdb_inode_t *serial;

    size_t inolen = zdbfs_inode_dir_size(inode->extend[0]);

    if(!(serial = malloc(inolen)))
        diep("serialize: malloc");

    // FIXME debug
    memset(serial, 0x42, inolen);

    // first copy the inode data
    memcpy(serial, inode, sizeof(zdb_inode_t));

    // then copy the dir struct
    zdb_dir_t *dir = inode->extend[0];
    memcpy(&serial->extend[0], dir, sizeof(zdb_dir_t));

    // then copy each directory entries
    uint8_t *ptr = (uint8_t *) serial + sizeof(zdb_inode_t) + sizeof(zdb_dir_t);

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        size_t length = zdbfs_direntry_size(entry);

        memcpy(ptr, entry, length);
        ptr += length;
    }

    // zdbd_fulldump(serial, inolen);

    buffer.buffer = serial;
    buffer.length = inolen;

    return buffer;

}

static buffer_t zdbfs_inode_serialize(zdb_inode_t *inode) {
    if(S_ISDIR(inode->mode))
        return zdbfs_inode_serialize_dir(inode);

    return zdbfs_inode_serialize_file(inode);
}

// first initialization of the fs
//
// entry 0 will be metadata about information regarding this
// filesystem and additionnal stuff
//
// entry 1 will be the root directory of the system, which will
// be empty in a first set
int zdbfs_create(zdbfs_t *fs) {
    zdb_reply_t *reply;
    char *msg = "zdbfs version 0.1 debug header";
    char *bmsg = "zdbfs block namespace";
    uint32_t expected = 0;

    printf("initial\n");

    // checking if entry 0 exists
    if((reply = zdb_get(fs->mdctx, 0))) {
        if(strncmp((char *) reply->value, "zdbfs ", 6) == 0) {
            printf("[+] init: metadata already contains a valid filesystem\n");
            zdb_free(reply);
            return 0;
        }
    }

    //
    // create initial entry
    //
    redisReply *zreply;

    // cannot use zdb_set because id 0 is special
    if(!(zreply = redisCommand(fs->mdctx, "SET %b %s", NULL, 0, msg)))
        diep("redis: set basic metadata");

    if(memcmp(zreply->str, &expected, zreply->len) != 0)
        dies("could not create initial message", zreply->str);

    freeReplyObject(zreply);


    //
    // create initial root directory (if not there)
    //
    if((reply = zdb_get(fs->mdctx, 1))) {
        printf("[+] init: metadata already contains a valid root directory\n");
        zdb_free(reply);
        return 0;
    }

    zdb_inode_t *inode = zdbfs_mkdir_empty(1, 0755);
    buffer_t root = zdbfs_inode_serialize(inode);

    if(zdb_set(fs->mdctx, 0, root.buffer, root.length) != 1)
        dies("could not create root directory", zreply->str);

    //
    // create initial block
    //
    if((reply = zdb_get(fs->datactx, 0))) {
        printf("[+] init: data already contains a valid signature\n");
        zdb_free(reply);
        return 0;
    }

    // cannot use zdb_set because id 0 is special
    if(!(zreply = redisCommand(fs->datactx, "SET %b %s", NULL, 0, bmsg)))
        diep("redis: set basic data");

    expected = 0;
    if(memcmp(zreply->str, &expected, zreply->len) != 0)
        dies("could not create initial data message", zreply->str);

    freeReplyObject(zreply);

    // FIXME
    // free(root.buffer);

    return 0;
}




static void zdbfs_inode_to_stat(struct stat *st, zdb_inode_t *inode) {
    st->st_mode = inode->mode;
    st->st_uid = inode->uid;
    st->st_gid = inode->gid;
    st->st_mode = inode->mode;
    st->st_ctim = zdbfs_time_sys(inode->ctime);
    st->st_mtim = zdbfs_time_sys(inode->mtime);
    st->st_atim = zdbfs_time_sys(inode->atime);
    st->st_size = inode->size;

    // FIXME
    st->st_nlink = 2;
    st->st_rdev = 0;
    st->st_dev = 0;
    st->st_blocks = 0;
}

static int zdbfs_inode_stat(fuse_req_t req, fuse_ino_t ino, struct stat *stbuf) {
    zdbfs_t *fs = fuse_req_userdata(req);
    uint32_t inoid = ino;
    zdb_reply_t *reply;

    zdbfs_debug("[+] stat: ino: %ld\n", ino);

    if(!(reply = zdb_get(fs->mdctx, inoid)))
        return -1;

    zdb_inode_t *inode = zdbfs_inode_deserialize(reply->value, reply->length);

	stbuf->st_ino = ino;
    zdbfs_inode_to_stat(stbuf, inode);

	return 0;
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

static zdb_inode_t *zdbfs_fetch_inode(fuse_req_t req, fuse_ino_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    zdb_reply_t *reply;

    zdbfs_debug("[+] inode: fetch: %ld\n", ino);

    // if we don't have any reply from zdb, entry doesn't exists
    if(!(reply = zdb_get(fs->mdctx, ino))) {
        zdbfs_debug("[+] inode: fetch: %lu: not found\n", ino);
        fuse_reply_err(req, ENOENT);
        return NULL;
    }

    zdb_inode_t *inode = zdbfs_inode_deserialize(reply->value, reply->length);
    // FIXME: free

    return inode;
}


static zdb_inode_t *zdbfs_fetch_directory(fuse_req_t req, fuse_ino_t ino) {
    zdb_inode_t *inode;

    zdbfs_debug("[+] directory: fetch: %ld\n", ino);

    if(!(inode = zdbfs_fetch_inode(req, ino)))
        return NULL;

    // checking if this inode is a directory
    if(!S_ISDIR(inode->mode)) {
        zdbfs_debug("[+] directory: %lu: not a directory\n", ino);
		fuse_reply_err(req, ENOTDIR);
        // FIXME: free
        return NULL;
    }

    return inode;
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

static zdb_inode_t *zdbfs_inode_new_file(fuse_req_t req, uint32_t mode) {
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    zdb_inode_t *create;

    if(!(create = calloc(sizeof(zdb_inode_t) + sizeof(zdb_blocks_t *), 1)))
        diep("inode: new file: malloc");

    create->mode = S_IFREG | mode;
    create->ctime = time(NULL);
    create->atime = create->ctime;
    create->mtime = create->ctime;
    create->uid = ctx->uid;
    create->gid = ctx->gid;
    create->size = 0;

    if(!(create->extend[0] = calloc(sizeof(zdb_blocks_t), 1)))
        diep("inode: new file: calloc");

    return create;
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

static size_t zdbfs_offset_to_block(off_t off) {
    size_t block = off / BLOCK_SIZE;
    printf("[+] offset %ld, block id: %lu\n", off, block);
    return block;
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

static void zdbfs_inode_set_block(zdb_inode_t *inode, size_t block, uint32_t blockid) {
    zdb_blocks_t *blocks = inode->extend[0];

    if(block + 1 > blocks->length) {
        if(!(inode->extend[0] = realloc(inode->extend[0], sizeof(uint32_t) * blocks->length + 1)))
            diep("blocks: realloc");

        blocks->length = block + 1;
    }

    blocks->blocks[block] = blockid;
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
