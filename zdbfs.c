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
#include <linux/fs.h>
#include "zdbfs.h"
#include "zdb.h"
#include "inode.h"

//
// volatile inode
//
// this is a special extension defined to auto-cleanup
// zdb_inode_t at the end of a function, adding 'volino'
// in front of a zdb_inode_t * variable will call the cleanup
// handler as soon as the function returns, whenever it is
//
// this ensure there is never any leak about inode inside
// a function without having to write free explicitly on each
// error case
//
#define volino __attribute__((cleanup(__cleanup_inode)))

void __cleanup_inode(void *p) {
    zdbfs_inode_free(* (zdb_inode_t **) p);
}

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
    #ifdef RELEASE
    (void) ino;
    (void) caller;
    #endif
    zdbfs_debug("[-] %s: ino %u: %s\n", caller, ino, strerror(err));
    fuse_reply_err(req, err);
}



//
// fuse syscall implementation
//
static void zdbfs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    struct stat stbuf;
    volino zdb_inode_t *inode = NULL;
    (void) fi;

    zdbfs_verbose("[+] syscall: getattr: ino: %ld\n", ino);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    zdbfs_inode_to_stat(&stbuf, inode, ino);

    fuse_reply_attr(req, &stbuf, ZDBFS_KERNEL_CACHE_TIME);
}

void zdbfs_fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    struct stat stbuf;
    (void) fi;

    zdbfs_verbose("[+] syscall: setattr: ino: %ld\n", ino);

    // fetching current inode state
    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

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
    if(zdbfs_inode_store(fs->mdctx, inode, ino) != ino)
        return zdbfs_fuse_error(req, EIO, ino);

    // send updated information back to caller
    zdbfs_inode_to_stat(&stbuf, inode, ino);
    fuse_reply_attr(req, &stbuf, ZDBFS_KERNEL_CACHE_TIME);
}

static void zdbfs_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    struct fuse_entry_param e;
    volino zdb_inode_t *directory = NULL;
    volino zdb_inode_t *inode = NULL;
    zdb_direntry_t *entry;

    zdbfs_verbose("[+] syscall: lookup: parent: %ld, name: %s\n", parent, name);

    if(!(directory = zdbfs_directory_fetch(req, parent)))
        return;

    // checking for entry in that directory
    if(!(entry = zdbfs_inode_lookup_direntry(directory, name)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    if(!(inode = zdbfs_inode_fetch(req, entry->ino)))
        return zdbfs_fuse_error(req, ENOENT, entry->ino);

    zdbfs_inode_to_fuse_param(&e, inode, entry->ino);
    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
    struct fuse_entry_param e;
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *create = NULL;
    uint32_t ino;

    zdbfs_verbose("[+] syscall: create: parent: %ld, name: %s\n", parent, name);

    if(!(inode = zdbfs_directory_fetch(req, parent)))
        return;

    // new file
    create = zdbfs_inode_new_file(req, mode);
    if((ino = zdbfs_inode_store(fs->mdctx, create, 0)) == 0)
        dies("create", "could not create inode");

    // update directory with new entry
    zdbfs_inode_dir_append(inode, ino, name);

    if(zdbfs_inode_store(fs->mdctx, inode, parent) != parent)
        dies("create", "could not update parent directory");

    zdbfs_inode_to_fuse_param(&e, create, ino);
    fuse_reply_create(req, &e, fi);
}

static void zdbfs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    struct fuse_entry_param e;
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *newdir = NULL;

    zdbfs_verbose("[+] syscall: mkdir: parent: %ld, name: %s\n", parent, name);

    if(!(inode = zdbfs_directory_fetch(req, parent)))
        return;

    // create new empty dir, sending it to the backend
    zdbfs_inode_new_dir(parent, mode);
    newdir->uid = ctx->uid;
    newdir->gid = ctx->gid;

    uint32_t ino;
    if((ino = zdbfs_inode_store(fs->mdctx, newdir, 0)) == 0)
        return zdbfs_fuse_error(req, EIO, 0);

    zdbfs_inode_dir_append(inode, ino, name);

    if(zdbfs_inode_store(fs->mdctx, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    zdbfs_inode_to_fuse_param(&e, newdir, ino);
    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    volino zdb_inode_t *inode = NULL;
    off_t limit = 0;

    zdbfs_verbose("[+] syscall: readdir: %lu: size: %lu, offset: %ld\n", ino, size, off);

    if(!(inode = zdbfs_directory_fetch(req, ino)))
        return;

    // fillin direntry with inode contents
    zdbfs_debug("[+] readdir: %lu: okay, fillin entries\n", ino);
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode);

    buffer_t buffer;
    buffer.length = 0;

    if(off == dir->length - 1) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    // first pass: computing total size
    for(off_t i = off; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        size_t entlen = fuse_add_direntry(req, NULL, 0, entry->name, NULL, 0);

        // if expected buffer length is too large
        // we won't fill it more
        if(buffer.length + entlen > size) {
            zdbfs_debug("[+] readdir: entry %ld will be too large, chunking\n", i);
            break;
        }

        buffer.length += entlen;
        limit += 1;
    }

    // allocate buffer large enough
    if(!(buffer.buffer = calloc(buffer.length, 1)))
        diep("readdir: calloc");

    // fill in the buffer for each entries
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    uint8_t *ptr = buffer.buffer;

    for(off_t i = off; i < off + limit; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        size_t cursize = fuse_add_direntry(req, NULL, 0, entry->name, NULL, 0);

        stbuf.st_ino = entry->ino;
        fuse_add_direntry(req, (char *) ptr, cursize, entry->name, &stbuf, i);

        ptr += cursize;
    }

    fuse_reply_buf(req, buffer.buffer, buffer.length);

    free(buffer.buffer);
}

static void zdbfs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;

    zdbfs_verbose("[+] syscall: open: ino %lu: request\n", ino);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    if(S_ISDIR(inode->mode))
        return zdbfs_fuse_error(req, EISDIR, ino);

    // FIXME: implement O_RDONLY, O_WRONLY, O_RDWR permission

    // FIXME: support O_APPEND

    // FIXME: support cache-writeback feature

    if(fi->flags & O_TRUNC) {
        zdbfs_debug("[+] open: truncating file %lu\n", ino);
        // FIXME: discard blocks ?
        inode->size = 0;
    }

    /*
    if((fi->flags & O_ACCMODE) != O_RDONLY) {
        fuse_reply_err(req, EACCES);
        return;
    }
    */

    // saving possible inode change (if nothing changed, set call will
    // have no effect on zdb size)
    if(zdbfs_inode_store(fs->mdctx, inode, ino) != ino)
        return zdbfs_fuse_error(req, EIO, ino);

    fuse_reply_open(req, fi);
}

static void zdbfs_fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    size_t fetched = 0;
    char *buffer;

    zdbfs_verbose("[+] syscall: read: ino %lu: size %lu, off: %lu\n", ino, size, off);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, EIO, ino);

    // zdbfs_inode_dump(inode);

    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);

    if(!(buffer = malloc(size)))
        diep("read: malloc buffer");

    // for each block to read
    while(fetched < size) {
        uint32_t block = zdbfs_offset_to_block(off);

        if(block >= blocks->length) {
            zdbfs_debug("[+] read: block ouf of bounds, eof reached\n");
            break;
        }

        uint32_t blockid = blocks->blocks[block];
        zdbfs_debug("[+] read: fetching block: %u [%u], fetched: %lu\n", block, blockid, fetched);

        zdb_reply_t *reply;
        if(!(reply = zdb_get(fs->datactx, blockid))) {
            free(buffer);
            return zdbfs_fuse_error(req, EIO, ino);
        }

        // fetched block contains something we need
        // the full block can be used, or partial content
        // partial content can be anywhere and any length inside
        // the block

        // checking if request is aligned with our block
        size_t alignment = (off % ZDBFS_BLOCK_SIZE);

        // computing remaining size to fetch
        size_t remain = size - fetched;

        // checking if the whole block can be used or not
        size_t chunk = (remain <= reply->length - alignment) ? remain : reply->length - alignment;

        zdbfs_debug("[+] read: copying %lu bytes (block align: %lu)\n", chunk, alignment);
        memcpy(buffer + fetched, reply->value + alignment, chunk);

        // cleaning block read
        zdb_free(reply);

        if(chunk == 0) {
            zdbfs_debug("[+] read: nothing more to read\n");
            break;
        }

        fetched += chunk;
        off += chunk;
    }

    fuse_reply_buf(req, buffer, fetched);

    free(buffer);
}

static void zdbfs_fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    size_t sent = 0;

    zdbfs_verbose("[+] syscall: write: ino %lu: size %lu, off: %lu\n", ino, size, off);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    // sending each blocks
    while(sent < size) {
        size_t block = zdbfs_offset_to_block(off + sent);
        size_t towrite = (size > ZDBFS_BLOCK_SIZE) ? ZDBFS_BLOCK_SIZE : size;
        uint32_t blockid = 0;

        blockid = zdbfs_inode_block_get(inode, block);
        if(blockid != 0)
            printf("REUSING EXISTING BLOCK: %u\n", blockid);

        zdbfs_debug("[+] write: writing %lu bytes (%lu / %lu, block: %u)\n", towrite, sent, size, blockid);

        if((blockid = zdb_set(fs->datactx, blockid, buf + sent, towrite)) == 0) {
            dies("write", "cannot write block to backend");
        }

        // FIXME ?
        zdbfs_inode_block_set(inode, block, blockid);

        sent += towrite;
    }

    if(off + size > inode->size)
        inode->size += sent;

    zdbfs_debug("[+] write: all blocks written (%lu bytes)\n", sent);
    if(zdbfs_inode_store(fs->mdctx, inode, ino) == 0) {
        dies("write", "could not update inode blocks");
    }

    fuse_reply_write(req, sent);
}

void zdbfs_fuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *newlink = NULL;
    volino zdb_inode_t *directory = NULL;
    uint32_t ino = 0;
    struct fuse_entry_param e;

    zdbfs_verbose("[+] syscall: symlink: ino %lu/%s -> %s\n", parent, name, link);

    // fetching original inode information
    if(!(directory = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // checking if destination does not already exists
    if(zdbfs_inode_lookup_direntry(directory, name))
        return zdbfs_fuse_error(req, EEXIST, parent);

    // create new symlink inode
    newlink = zdbfs_inode_new_symlink(req, link);

    // save new symlink inode
    if((ino = zdbfs_inode_store(fs->mdctx, newlink, 0)) == 0)
        return zdbfs_fuse_error(req, EIO, 0);

    // append new entry on the destination directory
    zdbfs_inode_dir_append(directory, ino, name);

    // saving new directory contents
    if(zdbfs_inode_store(fs->mdctx, directory, parent) != parent)
        return zdbfs_fuse_error(req, EIO, ino);

    zdbfs_inode_to_fuse_param(&e, newlink, ino);
    fuse_reply_entry(req, &e);
}

void zdbfs_fuse_readlink(fuse_req_t req, fuse_ino_t ino) {
    volino zdb_inode_t *inode = NULL;

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    const char *link = zdbfs_inode_symlink_get(inode);
    fuse_reply_readlink(req, link);
}

void zdbfs_fuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *newdir = NULL;
    struct fuse_entry_param e;

    zdbfs_verbose("[+] syscall: link: ino %lu -> %lu, %s\n", ino, newparent, newname);

    // fetching original inode information
    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    // fetching destination directory information
    if(!(newdir = zdbfs_inode_fetch(req, newparent)))
        return zdbfs_fuse_error(req, ENOENT, newparent);

    // checking if destination does not already exists
    if(zdbfs_inode_lookup_direntry(newdir, newname))
        return zdbfs_fuse_error(req, EEXIST, newparent);

    // create new entry on the destination directory
    zdbfs_inode_dir_append(newdir, ino, newname);

    // increase link-count of original inode
    inode->links += 1;

    // saving new directory contents
    if(zdbfs_inode_store(fs->mdctx, inode, ino) != ino)
        return zdbfs_fuse_error(req, EIO, ino);

    // saving inode information
    if(zdbfs_inode_store(fs->mdctx, newdir, newparent) != newparent)
        return zdbfs_fuse_error(req, EIO, newparent);

    zdbfs_inode_to_fuse_param(&e, inode, ino);
    fuse_reply_entry(req, &e);
}

void zdbfs_fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *file = NULL;
    zdb_direntry_t *entry;

    //
    // FIXME: no forget support
    //
    zdbfs_verbose("[+] syscall: unlink: parent %lu, name: %s\n", parent, name);

    // fetch parent directory
    if(!(inode = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // lookup for file entry in the directory
    if(!(entry = zdbfs_inode_lookup_direntry(inode, name)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // fetching inode information about the file
    if(!(file = zdbfs_inode_fetch(req, entry->ino)))
        return zdbfs_fuse_error(req, ENOENT, entry->ino);

    if(zdbfs_inode_unlink(req, file, entry->ino))
        return zdbfs_fuse_error(req, EIO, entry->ino);

    // remove file from directory list
    if(zdbfs_inode_remove_entry(inode, name) != 0)
        return zdbfs_fuse_error(req, ENOENT, parent);

    // save parent directory new list
    if(zdbfs_inode_store(fs->mdctx, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    // success
    fuse_reply_err(req, 0);
}

void zdbfs_fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *target = NULL;

    //
    // FIXME: no forget support
    //
    zdbfs_verbose("[+] syscall: rmdir: parent %lu, name: %s\n", parent, name);

    if(!(inode = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    zdb_direntry_t *expected;
    if(!(expected = zdbfs_inode_lookup_direntry(inode, name))) {
        zdbfs_debug("[+] rmdir: child not found (%s) on parent: %lu\n", name, parent);
        return zdbfs_fuse_error(req, ENOENT, parent);
    }

    zdbfs_debug("[+] rmdir: entry found, inspecting ino: %u\n", expected->ino);

    if(!(target = zdbfs_inode_fetch(req, expected->ino)))
        return zdbfs_fuse_error(req, ENOENT, expected->ino);

    zdb_dir_t *targetdir = zdbfs_inode_dir_get(target);
    if(targetdir->length > 2) {
        zdbfs_debug("[+] rmdir: target directory not empty (length: %u)\n", targetdir->length);
        return zdbfs_fuse_error(req, ENOTEMPTY, expected->ino);
    }

    // this should never fails since it matched just before
    if(zdbfs_inode_remove_entry(inode, name) != 0)
        return zdbfs_fuse_error(req, ENOENT, parent);

    if(zdbfs_inode_store(fs->mdctx, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    // success
    fuse_reply_err(req, 0);
}

// special handler for rename on the same directory
void zdbfs_fuse_rename_same(fuse_req_t req, fuse_ino_t parent, const char *name, const char *newname, unsigned int flags) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *directory = NULL;
    volino zdb_inode_t *existing = NULL;

    zdbfs_verbose("[+] syscall: rename: %lu, name: %s -> name: %s\n", parent, name, newname);

    if(!(directory = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // ensure source exists
    zdb_direntry_t *entry;
    if(!(entry = zdbfs_inode_lookup_direntry(directory, name)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    zdb_direntry_t *target;
    if((target = zdbfs_inode_lookup_direntry(directory, newname))) {
        zdbfs_debug("[+] rename: target already exists\n");

        // fetching target inode
        if(!(existing = zdbfs_inode_fetch(req, target->ino)))
            return zdbfs_fuse_error(req, EIO, target->ino);

        // target already exists
        // checking flags and unlink it if needed
        if(flags & RENAME_NOREPLACE)
            return zdbfs_fuse_error(req, EEXIST, target->ino);

        zdbfs_inode_unlink(req, existing, target->ino);

        // remove target from directory
        zdbfs_inode_remove_entry(directory, newname);
    }

    // remove original (flag it to delete)
    zdbfs_inode_remove_entry(directory, name);

    // create new direntry using same inode id
    zdbfs_inode_dir_append(directory, entry->ino, newname);

    // save updated parent
    if(zdbfs_inode_store(fs->mdctx, directory, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    fuse_reply_err(req, 0);
}

void zdbfs_fuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *old = NULL;
    volino zdb_inode_t *new = NULL;
    volino zdb_inode_t *existing = NULL;

    if(parent == newparent)
        return zdbfs_fuse_rename_same(req, parent, name, newname, flags);

    zdbfs_verbose("[+] syscall: rename: %lu, name: %s -> %lu, name: %s\n", parent, name, newparent, newname);

    // first checking old and new inodes
    if(!(old = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // only fetch new parent if it's another directory
    if(!(new = zdbfs_inode_fetch(req, newparent)))
        return zdbfs_fuse_error(req, ENOENT, newparent);

    // ensure source exists
    zdb_direntry_t *entry;
    if(!(entry = zdbfs_inode_lookup_direntry(old, name)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // check if target already exists
    zdb_direntry_t *nentry;
    if((nentry = zdbfs_inode_lookup_direntry(new, newname))) {
        zdbfs_debug("[+] rename: target already exists\n");

        if(!(existing = zdbfs_inode_fetch(req, nentry->ino)))
            return zdbfs_fuse_error(req, EIO, nentry->ino);

        // target already exists
        // checking flags and unlink it if needed
        if(flags & RENAME_NOREPLACE)
            return zdbfs_fuse_error(req, EEXIST, nentry->ino);

        zdbfs_inode_unlink(req, existing, nentry->ino);

        // remove target from directory
        zdbfs_inode_remove_entry(new, newname);
    }

    // remove original
    zdbfs_inode_remove_entry(old, name);

    // copy direntry and copy it to new parent
    zdbfs_inode_dir_append(new, entry->ino, newname);

    // save updated parents
    if(zdbfs_inode_store(fs->mdctx, old, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    // saving new parent if it's not the same
    if(zdbfs_inode_store(fs->mdctx, new, newparent) != newparent)
        return zdbfs_fuse_error(req, EIO, newparent);

    fuse_reply_err(req, 0);
}

void zdbfs_fuse_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    // zdbfs_t *fs = fuse_req_userdata(req);

    zdbfs_verbose("[+] syscall: flush: %lu\n", ino);

    // zdb_inode_t *inode = fs->icache[fi->fh];
    // zdbfs_inode_free(inode);

    fuse_reply_err(req, ENOSYS);
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
    .rmdir      = zdbfs_fuse_rmdir,
    .rename     = zdbfs_fuse_rename,
    .flush      = zdbfs_fuse_flush,
    .link       = zdbfs_fuse_link,
    .symlink    = zdbfs_fuse_symlink,
    .readlink   = zdbfs_fuse_readlink,
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

    // FIXME: cache handling
    // zdbfs.icache = (zdb_inode_t **) calloc(sizeof(zdb_inode_t *), 1024);

    // if(opts.singlethread)
    zdbfs_debug("[+] fuse: ready, waiting events\n");
    int ret = fuse_session_loop(se);
    (void) config;

    // config.clone_fd = opts.clone_fd;
    // config.max_idle_threads = 10;
    // int ret = fuse_session_loop_mt(se, &config);

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
