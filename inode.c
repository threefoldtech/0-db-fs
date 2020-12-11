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
#include "cache.h"

void zdbfs_inode_dump(zdb_inode_t *inode) {
    printf("[+] --- inode dump\n");
    printf("[+] mode: %x\n", inode->mode);
    printf("[+] is directory: %s\n", S_ISDIR(inode->mode) ? "yes" : "no");

    if(S_ISDIR(inode->mode)) {
        zdb_dir_t *dir = zdbfs_inode_dir_get(inode);
        printf("[+] directory length: %u\n", dir->length);

        for(size_t i = 0; i < dir->length; i++) {
            zdb_direntry_t *entry = dir->entries[i];
            printf("[+] directory content: %s [%u]\n", entry->name, entry->ino);
        }
    }

    if(S_ISREG(inode->mode)) {
        zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);
        printf("[+] blocks length: %lu\n", blocks->length);

        for(size_t i = 0; i < blocks->length; i++)
            printf("[+] inode block id: %u\n", blocks->blocks[i]);
    }

    printf("[+] --- inode dump\n");
}

static struct timespec zdbfs_time_sys(uint32_t source) {
    struct timespec ts = {
        .tv_sec = source,
        .tv_nsec = 0,
    };

    return ts;
}

size_t zdbfs_offset_to_block(off_t off) {
    size_t block = off / ZDBFS_BLOCK_SIZE;
    zdbfs_debug("[+] offset %ld = block: %lu\n", off, block);
    return block;
}

void zdbfs_inode_block_set(zdb_inode_t *inode, size_t block, uint32_t blockid) {
    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);

    if(block + 1 > blocks->length) {
        size_t newlength = sizeof(zdb_blocks_t) + (sizeof(uint32_t) * (block + 1));

        // FIXME
        if(!(inode->extend[0] = realloc(blocks, newlength)))
            diep("blocks: realloc");

        // update blocks pointer
        blocks = inode->extend[0];

        // initialize new blocks to zero
        for(size_t i = blocks->length; i < block; i++)
            blocks->blocks[i] = 0;

        blocks->length = block + 1;
    }

    blocks->blocks[block] = blockid;
}

uint32_t zdbfs_inode_block_get(zdb_inode_t *inode, size_t block) {
    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);

    // checking if block is already allocated
    if(block + 1 > blocks->length)
        return 0;

    // return allocated block
    return blocks->blocks[block];
}

size_t zdbfs_direntry_size(zdb_direntry_t *entry) {
    // deleted entry
    if(entry->size == 0)
        return 0;

    return sizeof(zdb_direntry_t) + entry->size + 1;
}

size_t zdbfs_inode_dir_size(zdb_dir_t *dir) {
    size_t length = sizeof(zdb_inode_t);
    length += sizeof(zdb_dir_t);

    for(size_t i = 0; i < dir->length; i++)
        length += zdbfs_direntry_size(dir->entries[i]);

    return length;
}

size_t zdbfs_inode_file_size(zdb_inode_t *inode) {
    size_t length = sizeof(zdb_inode_t);
    length += sizeof(zdb_blocks_t);

    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);
    length += blocks->length * ZDBFS_BLOCK_SIZE;

    return length;
}

zdb_dir_t *zdbfs_dir_new(uint32_t parent) {
    zdb_dir_t *dir;

    // initialize an empty directory in memory
    if(!(dir = malloc(sizeof(zdb_dir_t))))
        diep("dir: malloc");

    // fill it with the 2 default entries
    dir->length = 0;
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(parent, "."));
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(parent, ".."));
    // dir = zdbfs_dir_append(dir, zdbfs_direntry_new(42, "coucou"));

    return dir;
}

zdb_inode_t *zdbfs_inode_new_dir(uint32_t parent, uint32_t mode) {
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

    zdbfs_inode_dir_set(inode, dir);

    return inode;
}

//
// deserializer
//
zdb_inode_t *zdbfs_inode_deserialize_dir(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
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

zdb_inode_t *zdbfs_inode_deserialize_file(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    zdb_blocks_t *blocks = (zdb_blocks_t *) (buffer + sizeof(zdb_inode_t));

    if(!(inode->extend[0] = malloc(length - sizeof(zdb_inode_t))))
        diep("deserialize: file: malloc");

    memcpy(inode->extend[0], blocks, length - sizeof(zdb_inode_t));

    return inode;
}

zdb_inode_t *zdbfs_inode_deserialize_symlink(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    char *link = (char *) (buffer + sizeof(zdb_inode_t));

    if(!(inode->extend[0] = malloc(length - sizeof(zdb_inode_t))))
        diep("deserialize: symlink: malloc");

    memcpy(inode->extend[0], link, length - sizeof(zdb_inode_t));

    return inode;
}

zdb_inode_t *zdbfs_inode_deserialize(uint8_t *buffer, size_t length) {
    zdb_inode_t *inode;

    if(length < sizeof(zdb_inode_t))
        dies("deserialize", "wrong size from db");

    // allocate inode struct plus one pointer for extend
    if(!(inode = malloc(sizeof(zdb_inode_t) + sizeof(void *))))
        diep("deserialize: malloc inode");

    // copy inode from buffer to inode, as it
    memcpy(inode, buffer, sizeof(zdb_inode_t));

    // nothing more to do if it's not a directory
    if(S_ISLNK(inode->mode))
        return zdbfs_inode_deserialize_symlink(inode, buffer, length);

    // handling directory
    if(!S_ISDIR(inode->mode))
        return zdbfs_inode_deserialize_file(inode, buffer, length);

    // handling everything else as file
    return zdbfs_inode_deserialize_dir(inode, buffer, length);
}


//
// serializer
//

buffer_t zdbfs_inode_serialize_file(zdb_inode_t *inode) {
    buffer_t buffer;
    zdb_inode_t *serial;
    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);

    size_t blen = sizeof(zdb_blocks_t) + (blocks->length * sizeof(uint32_t));
    size_t inolen = sizeof(zdb_inode_t) + blen;

    if(!(serial = malloc(inolen)))
        diep("serialize: malloc");

    // FIXME debug
    memset(serial, 0x42, inolen);

    // first copy the inode data
    memcpy(serial, inode, sizeof(zdb_inode_t));

    // set blocks
    memcpy(&serial->extend[0], blocks, blen);

    // zdbd_fulldump(serial, inolen);

    buffer.buffer = serial;
    buffer.length = inolen;

    return buffer;
}

buffer_t zdbfs_inode_serialize_symlink(zdb_inode_t *inode) {
    buffer_t buffer;
    zdb_inode_t *serial;
    size_t inolen = sizeof(zdb_inode_t) + inode->size + 1;
    char *link = inode->extend[0];

    if(!(serial = calloc(inolen, 1)))
        diep("serialize: malloc");

    // FIXME debug
    memset(serial, 0x42, inolen);

    // first copy the inode data
    memcpy(serial, inode, sizeof(zdb_inode_t));

    // copy symlink destination to extend
    memcpy(&serial->extend[0], link, inode->size);

    // zdbd_fulldump(serial, inolen);

    buffer.buffer = serial;
    buffer.length = inolen;

    return buffer;
}

buffer_t zdbfs_inode_serialize_dir(zdb_inode_t *inode) {
    buffer_t buffer;
    zdb_inode_t *serial;
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode);
    size_t inolen = zdbfs_inode_dir_size(dir);

    if(!(serial = malloc(inolen)))
        diep("serialize: malloc");

    // FIXME debug
    memset(serial, 0x42, inolen);

    // first copy the inode data
    memcpy(serial, inode, sizeof(zdb_inode_t));

    // then copy the dir struct
    zdb_dir_t local = {.length = 0};

    // then copy each directory entries
    uint8_t *ptr = (uint8_t *) serial + sizeof(zdb_inode_t) + sizeof(zdb_dir_t);

    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];

        // deleted entry, do not serialize it
        if(entry->size == 0)
            continue;

        size_t length = zdbfs_direntry_size(entry);

        memcpy(ptr, entry, length);
        ptr += length;

        // count entries
        local.length += 1;
    }

    // copy dir header (count)
    memcpy(&serial->extend[0], &local, sizeof(zdb_dir_t));

    // zdbd_fulldump(serial, inolen);

    buffer.buffer = serial;
    buffer.length = inolen;

    return buffer;

}

buffer_t zdbfs_inode_serialize(zdb_inode_t *inode) {
    if(S_ISDIR(inode->mode))
        return zdbfs_inode_serialize_dir(inode);

    if(S_ISLNK(inode->mode))
        return zdbfs_inode_serialize_symlink(inode);

    return zdbfs_inode_serialize_file(inode);
}



zdb_direntry_t *zdbfs_direntry_new(uint32_t ino, const char *name) {
    zdb_direntry_t *entry;
    size_t namelen = strlen(name);

    if(!(entry = malloc(sizeof(zdb_direntry_t) + namelen + 1)))
        diep("direntry: malloc");

    entry->ino = ino;
    entry->size = namelen;
    strcpy(entry->name, name);

    return entry;
}

zdb_dir_t *zdbfs_dir_append(zdb_dir_t *dir, zdb_direntry_t *entry) {
    dir->length += 1;
    size_t entlen = sizeof(zdb_direntry_t *) * dir->length;

    if(!(dir = realloc(dir, sizeof(zdb_dir_t) + entlen)))
        diep("dir append: realloc");

    dir->entries[dir->length - 1] = entry;

    return dir;
}

zdb_dir_t *zdbfs_inode_dir_append(zdb_inode_t *inode, uint32_t ino, const char *name) {
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode);
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(ino, name));
    zdbfs_inode_dir_set(inode, dir);

    return dir;
}

//
// accessors
//
zdb_dir_t *zdbfs_inode_dir_get(zdb_inode_t *inode) {
    return inode->extend[0];
}

zdb_dir_t *zdbfs_inode_dir_set(zdb_inode_t *inode, zdb_dir_t *dir) {
    inode->extend[0] = dir;
    return dir;
}

zdb_blocks_t *zdbfs_inode_blocks_get(zdb_inode_t *inode) {
    return inode->extend[0];
}

void zdbfs_inode_to_fuse_param(struct fuse_entry_param *param, zdb_inode_t *inode, uint32_t ino) {
    memset(param, 0, sizeof(struct fuse_entry_param));

    param->ino = ino;
    param->attr_timeout = ZDBFS_KERNEL_CACHE_TIME;
    param->entry_timeout = ZDBFS_KERNEL_CACHE_TIME;

    zdbfs_inode_to_stat(&param->attr, inode, ino);
}

void zdbfs_inode_to_stat(struct stat *st, zdb_inode_t *inode, uint32_t ino) {
    // cleaning target stat struct
    memset(st, 0, sizeof(struct stat));

    st->st_ino = ino;
    st->st_mode = inode->mode;
    st->st_uid = inode->uid;
    st->st_gid = inode->gid;
    st->st_mode = inode->mode;
    st->st_ctim = zdbfs_time_sys(inode->ctime);
    st->st_mtim = zdbfs_time_sys(inode->mtime);
    st->st_atim = zdbfs_time_sys(inode->atime);
    st->st_size = inode->size;
    st->st_nlink = inode->links;

    // FIXME: does not reflect reality
    //        this try to match to nearest 512 bytes aligned
    //        value, but physical blocks are not rounded in reality
    st->st_blocks = (inode->size + (512 - (inode->size % 512))) / 512;

    // FIXME: not implemented
    st->st_rdev = 0;
    st->st_dev = 0;
}

void zdbfs_dir_free(zdb_dir_t *dir) {
    for(size_t i = 0; i < dir->length; i++)
        free(dir->entries[i]);

    free(dir);
}

void zdbfs_inode_free(zdb_inode_t *inode) {
    // do nothing on null inode
    if(!inode)
        return;

    if(S_ISDIR(inode->mode)) {
        // free directory entries
        zdbfs_dir_free(inode->extend[0]);
    }

    if(S_ISREG(inode->mode)) {
        // free file blocks
        free(inode->extend[0]);
    }

    if(S_ISLNK(inode->mode)) {
        // free link destination
        free(inode->extend[0]);
    }

    free(inode);
}

zdb_inode_t *zdbfs_inode_fetch(fuse_req_t req, fuse_ino_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    zdb_reply_t *reply;

    zdbfs_debug("[+] inode: fetch: %ld\n", ino);

    // if we don't have any reply from zdb, entry doesn't exists
    if(!(reply = zdb_get(fs->mdctx, ino))) {
        zdbfs_debug("[+] inode: fetch: %lu: not found\n", ino);
        // fuse_reply_err(req, ENOENT);
        return NULL;
    }

    zdb_inode_t *inode = zdbfs_inode_deserialize(reply->value, reply->length);
    zdb_free(reply);

    return inode;
}

zdb_inode_t *zdbfs_directory_fetch(fuse_req_t req, fuse_ino_t ino) {
    zdb_inode_t *inode;

    zdbfs_debug("[+] directory: fetch: %ld\n", ino);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return NULL;

    // checking if this inode is a directory
    if(!S_ISDIR(inode->mode)) {
        zdbfs_debug("[+] directory: %lu: not a directory\n", ino);
        fuse_reply_err(req, ENOTDIR);
        zdbfs_inode_free(inode);
        return NULL;
    }

    return inode;
}

uint32_t zdbfs_inode_store_backend(redisContext *backend, zdb_inode_t *inode, uint32_t ino) {
    buffer_t save = zdbfs_inode_serialize(inode);
    uint32_t inoret;

    inoret = zdb_set(backend, ino, save.buffer, save.length);

    // returns zero
    if(inoret == 0) {
        fprintf(stderr, "[-] zdbfs: store inode: failed\n");
        ino = 0;
    }

    free(save.buffer);

    return inoret;
}

uint32_t zdbfs_inode_store_metadata(fuse_req_t req, zdb_inode_t *inode, uint32_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    return zdbfs_inode_store_backend(fs->mdctx, inode, ino);
}

uint32_t zdbfs_inode_store_data(fuse_req_t req, zdb_inode_t *inode, uint32_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    return zdbfs_inode_store_backend(fs->datactx, inode, ino);
}

zdb_direntry_t *zdbfs_inode_lookup_direntry(zdb_inode_t *inode, const char *name) {
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode);

    for(size_t i = 0; i < dir->length; i++) {
        // lookup for each entry for the right one
        zdb_direntry_t *entry = dir->entries[i];
        if(strcmp(entry->name, name) == 0)
            return entry;
    }

    return NULL;
}

int zdbfs_inode_remove_entry(zdb_inode_t *inode, const char *name) {
    zdb_direntry_t *entry;

    if(!(entry = zdbfs_inode_lookup_direntry(inode, name)))
        return 1;

    // flag size as zero, will be skipped serialized
    zdbfs_debug("[+] inode: remove entry: entry found, deleting\n");

    // overwrite name (to avoid false match later)
    memset(entry->name, 0, entry->size);
    entry->size = 0;

    return 0;
}

//
// regular files
//
zdb_inode_t *zdbfs_inode_new_file(fuse_req_t req, uint32_t mode) {
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
    create->links = 1;

    if(!(create->extend[0] = calloc(sizeof(zdb_blocks_t), 1)))
        diep("inode: new file: calloc");

    return create;
}

//
// symlinks
//
zdb_inode_t *zdbfs_inode_new_symlink(fuse_req_t req, const char *link) {
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    size_t linklen = strlen(link) + 1;
    zdb_inode_t *symlink;

    if(!(symlink = calloc(sizeof(zdb_inode_t) + sizeof(char *), 1)))
        diep("inode: new file: calloc");

    symlink->mode = S_IFLNK | 0777;
    symlink->ctime = time(NULL);
    symlink->atime = symlink->ctime;
    symlink->mtime = symlink->ctime;
    symlink->uid = ctx->uid;
    symlink->gid = ctx->gid;
    symlink->size = linklen;
    symlink->links = 1;

    // copy link destination
    if(!(symlink->extend[0] = strdup(link)))
        diep("inode: symlink: strdup");

    return symlink;
}

const char *zdbfs_inode_symlink_get(zdb_inode_t *inode) {
    return inode->extend[0];
}

//
// deletion
//
int zdbfs_inode_blocks_remove(fuse_req_t req, zdb_inode_t *inode) {
    zdbfs_t *fs = fuse_req_userdata(req);
    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);

    for(size_t block = 0; block < blocks->length; block++) {
        uint32_t blockid = blocks->blocks[block];

        zdbfs_debug("[+] inode: delete: block %lu [%u]\n", block, blockid);

        if(zdb_del(fs->datactx, blockid) != 0)
            return 1;

        // invalidate deleted block
        blocks->blocks[block] = 0;
    }

    return 0;
}

// remove one link of the given inode
int zdbfs_inode_unlink(fuse_req_t req, zdb_inode_t *file, uint32_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // decrease amount of links
    file->links -= 1;

    // check if inode is not linked on the filesystem
    if(file->links == 0) {
        // delete blocks
        zdbfs_inode_blocks_remove(req, file);

        // delete inode itself
        if(zdb_del(fs->mdctx, ino) != 0)
            return 1;

    } else {
        // save updated links
        if(zdbfs_inode_store_metadata(req, file, ino) != ino)
            return 1;
    }

    return 0;
}

// first initialization of the fs
//
// entry 0 will be metadata about information regarding this
// filesystem and additionnal stuff
//
// entry 1 will be the root directory of the system, which will
// be empty in a first set
int zdbfs_initialize_filesystem(zdbfs_t *fs) {
    zdb_reply_t *reply;
    char *msg = "zdbfs version 0.1 debug header";
    char *bmsg = "zdbfs block namespace";
    uint32_t expected = 0;

    zdbfs_debug("[+] filesystem: checking backend\n");

    // checking if entry 0 exists
    if((reply = zdb_get(fs->mdctx, 0))) {
        if(strncmp((char *) reply->value, "zdbfs ", 6) == 0) {
            zdbfs_debug("[+] filesystem: metadata already contains a valid filesystem\n");
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
        zdbfs_debug("[+] filesystem: metadata already contains a valid root directory\n");
        zdb_free(reply);
        return 0;
    }

    zdb_inode_t *inode = zdbfs_inode_new_dir(1, 0755);
    if(zdbfs_inode_store_backend(fs->mdctx, inode, 0) != 1)
        dies("could not create root directory", zreply->str);

    zdbfs_inode_free(inode);

    //
    // create initial block
    //
    if((reply = zdb_get(fs->datactx, 0))) {
        zdbfs_debug("[+] init: data already contains a valid signature\n");
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

    return 0;
}


