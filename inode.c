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

void zdbfs_inode_dump(zdb_inode_t *inode) {
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

static struct timespec zdbfs_time_sys(uint32_t source) {
    struct timespec ts = {
        .tv_sec = source,
        .tv_nsec = 0,
    };

    return ts;
}

size_t zdbfs_offset_to_block(off_t off) {
    size_t block = off / BLOCK_SIZE;
    printf("[+] offset %ld, block id: %lu\n", off, block);
    return block;
}

void zdbfs_inode_set_block(zdb_inode_t *inode, size_t block, uint32_t blockid) {
    zdb_blocks_t *blocks = inode->extend[0];

    if(block + 1 > blocks->length) {
        if(!(inode->extend[0] = realloc(inode->extend[0], sizeof(uint32_t) * blocks->length + 1)))
            diep("blocks: realloc");

        blocks->length = block + 1;
    }

    blocks->blocks[block] = blockid;
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

    zdb_blocks_t *blocks = inode->extend[0];
    length += blocks->length * BLOCK_SIZE;

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
    dir = zdbfs_dir_append(dir, zdbfs_direntry_new(42, "coucou"));

    return dir;
}

zdb_inode_t *zdbfs_mkdir_empty(uint32_t parent, uint32_t mode) {
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
        diep("malloc");

    memcpy(inode->extend[0], blocks, length - sizeof(zdb_inode_t));

    return inode;
}

zdb_inode_t *zdbfs_inode_deserialize(uint8_t *buffer, size_t length) {
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

buffer_t zdbfs_inode_serialize_file(zdb_inode_t *inode) {
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

buffer_t zdbfs_inode_serialize_dir(zdb_inode_t *inode) {
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

size_t zdbfs_direntry_size(zdb_direntry_t *entry) {
    return sizeof(zdb_direntry_t) + entry->size + 1;
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

buffer_t zdbfs_inode_serialize(zdb_inode_t *inode) {
    if(S_ISDIR(inode->mode))
        return zdbfs_inode_serialize_dir(inode);

    return zdbfs_inode_serialize_file(inode);
}

void zdbfs_inode_to_stat(struct stat *st, zdb_inode_t *inode) {
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

int zdbfs_inode_stat(fuse_req_t req, fuse_ino_t ino, struct stat *stbuf) {
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

zdb_inode_t *zdbfs_fetch_inode(fuse_req_t req, fuse_ino_t ino) {
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


zdb_inode_t *zdbfs_fetch_directory(fuse_req_t req, fuse_ino_t ino) {
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

    if(!(create->extend[0] = calloc(sizeof(zdb_blocks_t), 1)))
        diep("inode: new file: calloc");

    return create;
}


