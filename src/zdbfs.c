#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <signal.h>
#include <linux/fs.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include "zdbfs.h"
#include "init.h"
#include "zdb.h"
#include "inode.h"
#include "cache.h"
#include "system.h"

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
#define volstr __attribute__((cleanup(__cleanup_malloc)))

#define zdbfs_macro_stats_incr(fs, field) { fs->stats.field += 1; }
#define zdbfs_macro_stats_add(fs, field, value) { fs->stats.field += value; }

void __cleanup_inode(void *p) {
    zdb_inode_t *x = * (zdb_inode_t **) p;
    if(x == NULL)
        return;

    if(x->ino == 0)
        zdbfs_inode_free(x);
}

void __cleanup_malloc(void *p) {
    void *x = * (void **) p;
    free(x);
}

//
// general helpers
//
int zdbfs_log_enabled(fuse_req_t req) {
    zdbfs_t *fs = fuse_req_userdata(req);
    return (fs->logfd != NULL);
}

void zdbfs_log(fuse_req_t req, char *call, const char *fmt, ...) {
    zdbfs_t *fs = fuse_req_userdata(req);
    va_list args;
    time_t timestamp = time(NULL);
    struct tm *ptime = localtime(&timestamp);
    char datestr[128];

    va_start(args, fmt);

    strftime(datestr, sizeof(datestr), "%Y-%m-%d %H:%M:%S", ptime);
    fprintf(fs->logfd, "%s [%s] ", datestr, call);
    vfprintf(fs->logfd, fmt, args);
    fprintf(fs->logfd, "\n");

    va_end(args);
}

// propagate an error to fuse with verbosity
void zdbfs_fuse_error(fuse_req_t req, int err, uint32_t ino) {
#ifdef RELEASE
    (void) ino;
#endif
    zdbfs_t *fs = fuse_req_userdata(req);
    zdbfs_macro_stats_incr(fs, errors);

    zdbfs_debug("[/] syscall: error reply: ino %u: %s\n", ino, strerror(err));
    fuse_reply_err(req, err);
}


//
// fuse syscall implementation
//
static void zdbfs_fuse_init(void *userdata, struct fuse_conn_info *conn) {
    (void) userdata;

    zdbfs_syscall("init", "[%d]", conn->want);
}

static void zdbfs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    struct stat stbuf;
    volino zdb_inode_t *inode = NULL;
    (void) fi;

    zdbfs_syscall("getattr", "ino: %ld", ino);
    zdbfs_macro_stats_incr(fs, syscall_getattr);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    zdbfs_inode_to_stat(&stbuf, inode, ino);

    fuse_reply_attr(req, &stbuf, ZDBFS_KERNEL_CACHE_TIME);
}

static void zdbfs_fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    struct stat stbuf;
    (void) fi;

    zdbfs_syscall("setattr", "ino: %ld", ino);
    zdbfs_macro_stats_incr(fs, syscall_setattr);

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
    if(zdbfs_inode_store_metadata(req, inode, ino) != ino)
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

    zdbfs_syscall("lookup", "parent: %ld, name: %s", parent, name);

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
    zdbfs_t *fs = fuse_req_userdata(req);
    struct fuse_entry_param e;
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *create = NULL;
    uint32_t ino;

    zdbfs_syscall("create", "parent: %ld, name: %s", parent, name);
    zdbfs_macro_stats_incr(fs, syscall_create);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, parent, name);
        zdbfs_log(req, "create", "%s [mode %o]", path, mode);
    }

    if(!(inode = zdbfs_directory_fetch(req, parent)))
        return;

    // new file
    create = zdbfs_inode_new_file(req, mode);
    if((ino = zdbfs_inode_store_metadata(req, create, 0)) == 0)
        return zdbfs_fuse_error(req, EIO, parent);

    // update directory with new entry
    zdbfs_inode_dir_append(inode, ino, name);

    if(zdbfs_inode_store_metadata(req, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    zdbfs_inode_to_fuse_param(&e, create, ino);
    fuse_reply_create(req, &e, fi);
}

static void zdbfs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    zdbfs_t *fs = fuse_req_userdata(req);
    struct fuse_entry_param e;
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *newdir = NULL;

    zdbfs_syscall("mkdir", "parent: %ld, name: %s", parent, name);
    zdbfs_macro_stats_incr(fs, syscall_mkdir);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, parent, name);
        zdbfs_log(req, "mkdir", "%s [mode %o]", path, mode);
    }

    if(!(inode = zdbfs_directory_fetch(req, parent)))
        return;

    // create new empty dir, sending it to the backend
    newdir = zdbfs_inode_new_dir(parent, mode);
    newdir->uid = ctx->uid;
    newdir->gid = ctx->gid;

    uint32_t ino;
    if((ino = zdbfs_inode_store_metadata(req, newdir, 0)) == 0)
        return zdbfs_fuse_error(req, EIO, 0);

    zdbfs_inode_dir_append(inode, ino, name);

    if(zdbfs_inode_store_metadata(req, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    zdbfs_inode_to_fuse_param(&e, newdir, ino);
    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    (void) fi;
    volino zdb_inode_t *inode = NULL;
    off_t limit = 0;

    zdbfs_syscall("readdir", "ino: %lu, size: %lu, offset: %ld", ino, size, off);
    zdbfs_macro_stats_incr(fs, syscall_readdir);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, ino, NULL);
        zdbfs_log(req, "readdir", "%s", path);
    }

    if(!(inode = zdbfs_directory_fetch(req, ino))) {
        printf("FAILED\n");
        return;
    }

    // fillin direntry with inode contents
    zdbfs_debug("[+] readdir: %lu: okay, fillin entries\n", ino);
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode);

    zdbfs_debug("[+] readdir: total entries: %u\n", dir->length);

    buffer_t buffer;
    buffer.length = 0;

    if(off >= dir->length) {
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
        zdbfs_sysfatal("readdir: calloc");

    // fill in the buffer for each entries
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    uint8_t *ptr = buffer.buffer;

    for(off_t i = off; i < off + limit; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        size_t cursize = fuse_add_direntry(req, NULL, 0, entry->name, NULL, 0);

        stbuf.st_ino = entry->ino;
        fuse_add_direntry(req, (char *) ptr, cursize, entry->name, &stbuf, i + 1);

        ptr += cursize;
    }

    fuse_reply_buf(req, buffer.buffer, buffer.length);

    free(buffer.buffer);
}

static void zdbfs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;

    zdbfs_syscall("open", "ino %lu: request", ino);
    zdbfs_macro_stats_incr(fs, syscall_open);

    if(zdbfs_log_enabled(req)) {
        zdbfs_log(req, "open", "inode %ld", ino);
    }

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    if(S_ISDIR(inode->mode))
        return zdbfs_fuse_error(req, EISDIR, ino);

    if(fi->flags & O_RDONLY) {
        zdbfs_debug("[+] open: read only requested %lu\n", ino);
        fuse_reply_open(req, fi);
        return;
    }

    // FIXME: implement O_RDONLY, O_WRONLY, O_RDWR permission

    // FIXME: support O_APPEND

    // FIXME: support cache-writeback feature

    if(fi->flags & O_TRUNC) {
        zdbfs_debug("[+] open: truncating file %lu\n", ino);
        // FIXME: discard blocks ?
        inode->size = 0;

        // saving possible inode change (if nothing changed, set call will
        // have no effect on zdb size)
        if(zdbfs_inode_store_metadata(req, inode, ino) != ino)
            return zdbfs_fuse_error(req, EIO, ino);

        fuse_reply_open(req, fi);
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
    zdbfs_t *fs = fuse_req_userdata(req);
    (void) fi;
    volino zdb_inode_t *inode = NULL;
    size_t fetched = 0;
    char *buffer;
    off_t ooff = off; // copy original offset

    zdbfs_syscall("read", "ino %lu: size %lu, off: %lu", ino, size, off);
    zdbfs_macro_stats_incr(fs, syscall_read);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, EIO, ino);

    // zdbfs_inode_dump(inode);

    if(!(buffer = calloc(size, 1)))
        zdbfs_sysfatal("read: buffer: malloc");

    // for each block to read
    while(fetched < size) {
        uint32_t block = zdbfs_offset_to_block(off);

        // checking if request is aligned with our block
        size_t alignment = (off % ZDBFS_BLOCK_SIZE);

        if(zdbfs_inode_block_get(inode, block) == 0) {
            // block id from requested offset returned 0
            // this mean this block doesn't exists _or_ the block
            // is set to 0, if the block doesn't contains any data
            // if it's a hole, in case of a hole, we need to returns
            // valid response and not truncated response
            zdbfs_debug("[+] read: requested block does not exists or empty\n");

            size_t eob = ZDBFS_BLOCK_SIZE - alignment;
            zdbfs_debug("[+] read: skipping this block, moving forward: %lu bytes\n", eob);

            fetched += eob;
            off += eob;

            continue;
        }

        zdb_reply_t *reply;
        if(!(reply = zdbfs_inode_block_fetch(req, inode, ino, block))) {
            free(buffer);
            return zdbfs_fuse_error(req, EIO, ino);
        }

        if(reply->length < alignment) {
            zdbfs_debug("[+] read: try to read further than any data on this block\n");
            zdbfs_zdb_reply_free(reply);

            // act like block were not found, we don't have
            // any data useful on this block, we are probably in
            // a hole
            size_t eob = ZDBFS_BLOCK_SIZE - alignment;

            fetched += eob;
            off += eob;

            continue;
        }

        // fetched block contains something we need
        // the full block can be used, or partial content
        // partial content can be anywhere and any length inside
        // the block

        // computing remaining size to fetch
        size_t remain = size - fetched;

        // checking if the whole block can be used or not
        size_t chunk = (remain <= reply->length - alignment) ? remain : reply->length - alignment;

        zdbfs_debug("[+] read: copying %lu bytes (block align: %lu)\n", chunk, alignment);
        memcpy(buffer + fetched, reply->value + alignment, chunk);

        // cleaning block read
        zdbfs_zdb_reply_free(reply);

        if(chunk == 0) {
            if(ooff + fetched >= inode->size) {
                // eof reached
                zdbfs_debug("[+] read: nothing more to read [%lu >= %lu]\n", off + fetched, inode->size);
                break;
            }

            zdbfs_debug("[+] read: nothing left on that block, trying next one\n");
            // block doesn't contains any relevant data anymore
            // let's try maybe next block (if any, if none, will
            // fails on the beginin of the next loop)
            chunk = ZDBFS_BLOCK_SIZE - alignment;

            zdbfs_debug("[+] read: skipping last %lu bytes to reach next block\n", chunk);
        }

        fetched += chunk;
        off += chunk;
    }

    // avoid overrun if we skipped hole larger
    // than expected
    if(fetched > size)
        fetched = size;

    // if the chunk requested is in range of the file
    // we are maybe inside a hole and we need to reply
    // the full length
    if(off + size < inode->size && fetched != size) {
        zdbfs_debug("[+] read: growing chunk read, hole possible\n");
        fetched = size;
    }

    zdbfs_macro_stats_add(fs, read_bytes, fetched);
    fuse_reply_buf(req, buffer, fetched);

    free(buffer);
}

static void zdbfs_fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    zdb_reply_t *reply;
    size_t sent = 0;

    zdbfs_syscall("write", "ino %lu: size %lu, off: %lu", ino, size, off);
    zdbfs_macro_stats_incr(fs, syscall_write);

    // fetch file inode which contains blockslist
    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    // sending each blocks
    while(sent < size) {
        // set blockid as 0 (insert new)
        uint32_t blockid = 0;

        // alignment is the offset inside this block
        uint32_t alignment = (off + sent) % ZDBFS_BLOCK_SIZE;

        // compute which block we use at this offset
        size_t block = zdbfs_offset_to_block(off + sent);

        // compute how many bytes to write _maximum_ on this chunk
        // this can be larger than blocksize
        size_t towrite = (size - sent > ZDBFS_BLOCK_SIZE) ? ZDBFS_BLOCK_SIZE : size - sent;

        // keep track of this chunk length
        size_t writepass = towrite;

        // link buffer to global allocated buffer
        char *buffer = fs->tmpblock;

        // if there are any alignment, we need to take it in account
        if(towrite + alignment > ZDBFS_BLOCK_SIZE)
            writepass = ZDBFS_BLOCK_SIZE - alignment;

        // set this chunk size
        // size_t blocksize = alignment + writepass;
        size_t blocksize = alignment + writepass;

        zdbfs_debug("[+] write: block alignment: %u, write: %lu, pass: %lu\n", alignment, towrite, writepass);

        // FIXME: optimize ?
        memset(fs->tmpblock, 0, ZDBFS_BLOCK_SIZE);

        blockid = zdbfs_inode_block_get(inode, block);
        if(blockid != 0) {
            // target block found on the blockslist, which mean
            // the block already exists in the backend, we need
            // to fetch this block to update it with new data
            zdbfs_debug("[+] write: block already in the backend: %u\n", blockid);

            // resize this block size by expected buffer length
            // following inline move
            blocksize = alignment + writepass;

            // fetch the block from backend
            if(!(reply = zdbfs_inode_block_fetch(req, inode, ino, block)))
                return zdbfs_fuse_error(req, EIO, ino);

            if(reply->length > ZDBFS_BLOCK_SIZE) {
                // critical: the fetched block from backend is larger
                // than our configured blocksize, we can't do anything
                // with this, blocklist is not inline with backend
                printf("[-] write: block read from backend larger than our blocksize\n");
                zdbfs_zdb_reply_free(reply);
                return zdbfs_fuse_error(req, EINVAL, ino);
            }

            // if fetched block is larger than what we need to write
            // updating blocksize to read size, we will write only on
            // the expected segment but send the full block
            if(reply->length > blocksize)
                blocksize = reply->length;

            // copying block from backend into temporarily buffer
            memcpy(buffer, reply->value, reply->length);

            // FIXME
            zdbfs_zdb_reply_free(reply);
        }

        zdbfs_debug("[+] write: writing %lu bytes segment\n", writepass);
        zdbfs_debug("[+] write: block write: %lu bytes (sent: %lu, block: %u)\n", blocksize, sent, blockid);

        // merge existing block buffer with write chunk
        memcpy(buffer + alignment, buf + sent, writepass);

        // send block to the backend, this can be a new block or an existing
        // block updated
        if((blockid = zdbfs_inode_block_store(req, inode, ino, block, buffer, blocksize)) == 0)
            return zdbfs_fuse_error(req, zdb_errno, ino);

        // jump to the next chunk to write
        sent += writepass;
    }

    if(off + size > inode->size)
        inode->size = off + size;

    zdbfs_debug("[+] write: all blocks written (%lu bytes)\n", sent);
    if(zdbfs_inode_store_metadata(req, inode, ino) == 0)
        return zdbfs_fuse_error(req, zdb_errno, 0);

    zdbfs_macro_stats_add(fs, write_bytes, sent);
    fuse_reply_write(req, sent);
}

static void zdbfs_fuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *newlink = NULL;
    volino zdb_inode_t *directory = NULL;
    uint32_t ino = 0;
    struct fuse_entry_param e;

    zdbfs_syscall("symlink", "ino %lu/%s -> %s", parent, name, link);
    zdbfs_macro_stats_incr(fs, syscall_symlink);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, parent, name);
        zdbfs_log(req, "symlink", "%s -> %s", path, link);
    }

    // fetching original inode information
    if(!(directory = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // checking if destination does not already exists
    if(zdbfs_inode_lookup_direntry(directory, name))
        return zdbfs_fuse_error(req, EEXIST, parent);

    // create new symlink inode
    newlink = zdbfs_inode_new_symlink(req, link);

    // save new symlink inode
    if((ino = zdbfs_inode_store_metadata(req, newlink, 0)) == 0)
        return zdbfs_fuse_error(req, EIO, 0);

    // append new entry on the destination directory
    zdbfs_inode_dir_append(directory, ino, name);

    // saving new directory contents
    if(zdbfs_inode_store_metadata(req, directory, parent) != parent)
        return zdbfs_fuse_error(req, EIO, ino);

    zdbfs_inode_to_fuse_param(&e, newlink, ino);
    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_readlink(fuse_req_t req, fuse_ino_t ino) {
    volino zdb_inode_t *inode = NULL;

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    const char *link = zdbfs_inode_symlink_get(inode);
    fuse_reply_readlink(req, link);
}

static void zdbfs_fuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *newdir = NULL;
    struct fuse_entry_param e;

    zdbfs_syscall("link", "ino %lu -> %lu, %s", ino, newparent, newname);
    zdbfs_macro_stats_incr(fs, syscall_link);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, newparent, newname);
        zdbfs_log(req, "link", "%lu -> %s", ino, path);
    }

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
    if(zdbfs_inode_store_metadata(req, inode, ino) != ino)
        return zdbfs_fuse_error(req, EIO, ino);

    // saving inode information
    if(zdbfs_inode_store_metadata(req, newdir, newparent) != newparent)
        return zdbfs_fuse_error(req, EIO, newparent);

    zdbfs_inode_to_fuse_param(&e, inode, ino);
    fuse_reply_entry(req, &e);
}

static void zdbfs_fuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *file = NULL;
    zdb_direntry_t *entry;
    int linkinfo;

    //
    // FIXME: no forget support
    //
    zdbfs_syscall("unlink", "parent %lu, name: %s", parent, name);
    zdbfs_macro_stats_incr(fs, syscall_unlink);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, parent, name);
        zdbfs_log(req, "unlink", "%s", path);
    }

    // fetch parent directory
    if(!(inode = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // lookup for file entry in the directory
    if(!(entry = zdbfs_inode_lookup_direntry(inode, name)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // fetching inode information about the file
    if(!(file = zdbfs_inode_fetch(req, entry->ino)))
        return zdbfs_fuse_error(req, ENOENT, entry->ino);

    // remove blocks
    if((linkinfo = zdbfs_inode_unlink(req, file, entry->ino)) == 1)
        return zdbfs_fuse_error(req, EIO, entry->ino);

    // reset file pointer if dropped
    if(linkinfo == 0)
        file = NULL; // avoid volino double free

    // remove file from directory list
    if(zdbfs_inode_remove_entry(inode, name) != 0)
        return zdbfs_fuse_error(req, ENOENT, parent);

    // save parent directory new list
    if(zdbfs_inode_store_metadata(req, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    // success
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *target = NULL;
    inocache_t *inocache;

    //
    // FIXME: no forget support
    //
    zdbfs_syscall("rmdir", "parent %lu, name: %s", parent, name);
    zdbfs_macro_stats_incr(fs, syscall_rmdir);

    if(zdbfs_log_enabled(req)) {
        volstr char *path = zdbfs_inode_resolv(req, parent, NULL);
        zdbfs_log(req, "rmdir", "%s", path);
    }

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

    // invalidate cache if present
    if((inocache = zdbfs_cache_get(req, expected->ino))) {
        zdbfs_debug("[+] rmdir: target inode still in cache, cleaning\n");
        zdbfs_cache_drop(req, inocache);
    }

    // remove inode from backend
    if(zdb_del(fs->metactx, expected->ino) != 0)
        return zdbfs_fuse_error(req, EIO, expected->ino);

    // this should never fails since it matched just before
    if(zdbfs_inode_remove_entry(inode, name) != 0)
        return zdbfs_fuse_error(req, ENOENT, parent);

    if(zdbfs_inode_store_metadata(req, inode, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    // success
    fuse_reply_err(req, 0);
}

// special handler for rename on the same directory
static void zdbfs_fuse_rename_same(fuse_req_t req, fuse_ino_t parent, const char *name, const char *newname, unsigned int flags) {
    volino zdb_inode_t *directory = NULL;
    volino zdb_inode_t *existing = NULL;
    uint32_t sourceino = 0;
    int linkinfo;

    zdbfs_syscall("rename", "%lu, name: %s -> name: %s", parent, name, newname);

    if(zdbfs_log_enabled(req)) {
        zdbfs_log(req, "rename", "%ld: %s -> %s", parent, name, newname);
    }

    if(!(directory = zdbfs_inode_fetch(req, parent)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // ensure source exists
    zdb_direntry_t *entry;
    if(!(entry = zdbfs_inode_lookup_direntry(directory, name)))
        return zdbfs_fuse_error(req, ENOENT, parent);

    // keep track of the source inode id
    sourceino = entry->ino;

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

        if((linkinfo = zdbfs_inode_unlink(req, existing, target->ino)) == 1)
            return zdbfs_fuse_error(req, EIO, entry->ino);

        // reset file pointer if dropped
        if(linkinfo == 0)
            existing = NULL; // avoid volino double free

        // remove target from directory
        zdbfs_inode_remove_entry(directory, newname);
    }

    // remove original (flag it to delete)
    zdbfs_inode_remove_entry(directory, name);

    // create new direntry using same inode id
    zdbfs_inode_dir_append(directory, sourceino, newname);

    // save updated parent
    if(zdbfs_inode_store_metadata(req, directory, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags) {
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *old = NULL;
    volino zdb_inode_t *new = NULL;
    volino zdb_inode_t *existing = NULL;
    uint32_t sourceino = 0;

    zdbfs_macro_stats_incr(fs, syscall_rename);

    if(parent == newparent)
        return zdbfs_fuse_rename_same(req, parent, name, newname, flags);

    zdbfs_syscall("rename", "%lu, name: %s -> %lu, name: %s", parent, name, newparent, newname);

    if(zdbfs_log_enabled(req)) {
        volstr char *path1 = zdbfs_inode_resolv(req, parent, name);
        volstr char *path2 = zdbfs_inode_resolv(req, newparent, newname);
        zdbfs_log(req, "rename", "%s -> %s", path1, path2);
    }

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

    // keep track of the source inode id
    sourceino = entry->ino;

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

        if(zdbfs_inode_unlink(req, existing, nentry->ino) == 0) {
            // unlink removed cache already, should
            // not be freed another time later
            existing = NULL;
        }

        // remove target from directory
        zdbfs_inode_remove_entry(new, newname);
    }

    // remove original
    zdbfs_inode_remove_entry(old, name);

    // copy direntry and copy it to new parent
    zdbfs_inode_dir_append(new, sourceino, newname);

    // save updated parents
    if(zdbfs_inode_store_metadata(req, old, parent) != parent)
        return zdbfs_fuse_error(req, EIO, parent);

    // saving new parent if it's not the same
    if(zdbfs_inode_store_metadata(req, new, newparent) != newparent)
        return zdbfs_fuse_error(req, EIO, newparent);

    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;

    zdbfs_syscall("flush", "ino: %lu", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    inocache_t *inocache;

    zdbfs_syscall("release", "ino: %lu", ino);

    if(!(inocache = zdbfs_cache_get(req, ino))) {
        zdbfs_debug("[+] release: entry not found in cache, nothing to do\n");
        fuse_reply_err(req, 0);
        return;
    }

    // release
    if(zdbfs_cache_release(req, inocache) == 0)
        return zdbfs_fuse_error(req, zdb_errno, ino);

    // zdbfs_inode_dump(inocache->inode);

    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void) fi;
    (void) datasync;

    zdbfs_syscall("fsync", "ino: %lu", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    zdbfs_syscall("forget", "ino: %lu, nlookup: %lu", ino, nlookup);
    fuse_reply_none(req);
}

static void zdbfs_fuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;

    zdbfs_syscall("opendir", "ino: %lu", ino);
    fuse_reply_open(req, fi);
}

static void zdbfs_fuse_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;

    zdbfs_syscall("releasedir", "ino: %lu", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void) fi;
    (void) datasync;

    zdbfs_syscall("fsyncdir", "ino: %lu", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_statfs(fuse_req_t req, fuse_ino_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    zdb_nsinfo_t *metadata;
    zdb_nsinfo_t *data;
    (void) ino;

    zdbfs_syscall("statfs", "ino: %lu", ino);
    zdbfs_macro_stats_incr(fs, syscall_statsfs);

    if(!(metadata = zdb_nsinfo(fs->metactx, fs->opts->meta_ns)))
        return zdbfs_fuse_error(req, EIO, ino);

    if(!(data = zdb_nsinfo(fs->datactx, fs->opts->data_ns)))
        return zdbfs_fuse_error(req, EIO, ino);

    // hardcode 10G for debug
    uint64_t sizefs = 10ull * 1024 * 1024 * 1024;
    size_t fragment = 1024;  // optional, could be 1 and no division

    // maximum inodes is uint32_t maximun value
    // (maximum keys available on namespace)

    // available inodes is total inodes without
    // current amount of entries
    // FIXME: should be substracted by next entries

    struct statvfs vfs = {
        .f_bsize = ZDBFS_BLOCK_SIZE,
        .f_frsize = fragment,
        .f_blocks = sizefs / fragment,
        .f_bfree = (sizefs - data->datasize) / fragment,
        .f_bavail = (sizefs - data->datasize) / fragment,
        .f_files = 0xffffffff,
        .f_ffree = 0xffffffff - metadata->entries,
        .f_favail = 0xffffffff - metadata->entries,
        .f_fsid = 1,
        .f_flag = 0,
        .f_namemax = 255,
    };

    free(metadata);
    free(data);

    fuse_reply_statfs(req, &vfs);
}

static void zdbfs_fuse_ioctl(fuse_req_t req, fuse_ino_t ino, int _cmd, void *arg, struct fuse_file_info *fi, unsigned flags, const void *in, size_t insz, size_t outsz) {
    unsigned int cmd = (unsigned int) _cmd;
    zdbfs_t *fs = fuse_req_userdata(req);
    (void) arg;
    (void) in;
    (void) insz;
    (void) outsz;
    (void) fi;

    zdbfs_syscall("ioctl", "ino: %lu, cmd: %u", ino, cmd);
    zdbfs_macro_stats_incr(fs, syscall_ioctl);

    if(flags & FUSE_IOCTL_COMPAT)
        return zdbfs_fuse_error(req, ENOSYS, ino);

    // checking which ioctl requested
    if(cmd == ZDBFS_IOCTL_SNAPSHOT) {
        zdbfs_debug("[+] ioctl: snapshot: requested\n");

        size_t flushed = zdbfs_cache_clean(fs);
        zdbfs_debug("[+] ioctl: snapshot: cache flushed: %lu entries\n", flushed);

        uint64_t now = time(NULL);
        fuse_reply_ioctl(req, 0, &now, sizeof(uint64_t));
        return;
    }

    if(cmd == ZDBFS_IOCTL_STATISTICS) {
        zdbfs_debug("[+] ioctl: statistics: requested\n");

        fuse_reply_ioctl(req, 0, &fs->stats, sizeof(stats_t));
        return;
    }


    // invalid ioctl
    zdbfs_fuse_error(req, EINVAL, ino);
}

static void zdbfs_stats_dump(zdbfs_t *fs) {
    stats_t *s = &fs->stats;

    printf("[+] stats: fuse: requests: %lu\n", s->fuse_reqs);
}

// custom event loop made around libfuse
// this event loop mostly just introduce an async read of
// the fuse file descriptor with a custom timeout
//
// this enable the process to do background tasks when the filesystem
// is not under heavy load
int zdbfs_fuse_session_loop(struct fuse_session *se, zdbfs_t *fs, int timeout) {
	int res = 0;
    int ffd;
    int evfd;
    struct epoll_event event;
    struct epoll_event *events = NULL;
    size_t proceed = 0;
	struct fuse_buf fbuf = {
		.mem = NULL,
	};

    // initialize empty struct
    memset(&event, 0, sizeof(struct epoll_event));

    // fetch fuse file descriptor
    ffd = fuse_session_fd(se);

    // initialize epoll with fuse file descriptor
    if((evfd = epoll_create1(0)) < 0)
        zdbfs_sysfatal("fuse: loop: epoll_create1");

    event.data.fd = ffd;
    event.events = EPOLLIN;

    // only watch for read event
    if(epoll_ctl(evfd, EPOLL_CTL_ADD, ffd, &event) < 0)
        zdbfs_sysfatal("fuse: loop: epoll_ctl");

    if(!(events = calloc(ZDBFS_EPOLL_MAXEVENTS, sizeof event)))
        zdbfs_sysfatal("fuse: loop: events: calloc");

    //
    // main fuse loop (single threaded)
    //
    while(!fuse_session_exited(se)) {
        int n = epoll_wait(evfd, events, ZDBFS_EPOLL_MAXEVENTS, timeout);

        // call background cache scrubbing it
        // there is a timeout (filesystem not under pressure)
        // or if we proceed for specific amount of requests
        //
        // if the filesystem is under pressure, there can be
        // no timeout for a long time and cache can be filled up
        // quickly, this force scrubbing to happen
        if(n == 0 || proceed > 8192) {
            // zdbfs_cache_stats(fs);
            size_t flushed = zdbfs_cache_sync(fs);

            if(flushed > 0) {
                zdbfs_debug("[+] cache: flushed %lu inodes\n", flushed);

                if(fs->logfd)
                    fflush(fs->logfd);
            }

            // reset request counter
            proceed = 0;
            continue;
        }

        // fuse session is terminated if signal
        // handler was executed, this function won't be
        // interrupted by signal
        if(fuse_session_exited(se))
            break;

        res = fuse_session_receive_buf(se, &fbuf);
        proceed += 1;

        if(res == -EINTR)
            continue;

        if(res <= 0)
            break;

        fuse_session_process_buf(se, &fbuf);
        fs->stats.fuse_reqs += 1;
    }

    free(fbuf.mem);
    free(events);

    if(res > 0)
        res = 0;

    fuse_session_reset(se);
    return res;
}

static const struct fuse_lowlevel_ops zdbfs_fuse_oper = {
    .init       = zdbfs_fuse_init,
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
    .release    = zdbfs_fuse_release,
    .fsync      = zdbfs_fuse_fsync,
    .forget     = zdbfs_fuse_forget,
    .opendir    = zdbfs_fuse_opendir,
    .releasedir = zdbfs_fuse_releasedir,
    .fsyncdir   = zdbfs_fuse_fsyncdir,
    .statfs     = zdbfs_fuse_statfs,
    .ioctl      = zdbfs_fuse_ioctl,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts fopts;
    zdbfs_t zdbfs;

    zdbfs_info("initializing zdbfs v%s", ZDBFS_VERSION);

    // catch segmentation fault for backtrace
    zdbfs_system_signal(SIGSEGV, zdbfs_system_sighandler);

    if(zdbfs_init_args(&zdbfs, &args, &fopts) != 0)
        return 1;

    if(zdbfs_init_runtime(&zdbfs) != 0)
        return 1;

    if(zdbfs_zdb_connect(&zdbfs) != 0)
        return 1;

    zdbfs_inode_init(&zdbfs);

    //
    // fuse initialization
    //
    zdbfs_debug("[+] fuse: initializing session\n");
    if(!(se = fuse_session_new(&args, &zdbfs_fuse_oper, sizeof(zdbfs_fuse_oper), &zdbfs)))
        return 1;

    zdbfs_debug("[+] fuse: initializing signals\n");
    if(fuse_set_signal_handlers(se) != 0)
        return 1;

    zdbfs_debug("[+] fuse: mounting session\n");
    if(fuse_session_mount(se, fopts.mountpoint) != 0)
        return 1;

    //
    // processing events
    //
    zdbfs_success("fuse: ready, waiting events: %s", fopts.mountpoint);

    if(zdbfs.background) {
        zdbfs_debug("[+] fuse: forking, going to background\n");
        fuse_daemonize(0);
    }

    int ret = zdbfs_fuse_session_loop(se, &zdbfs, 1000);
    // (void) config;

    //
    // cleaning up
    //
    printf("\n[+] fuse: stopping filesystem\n");

    printf("[+] cache: forcing cache flush\n");
    size_t flushed = zdbfs_cache_clean(&zdbfs);
    printf("[+] cache: flushed, %lu entries written\n", flushed);

    zdbfs_stats_dump(&zdbfs);
    zdbfs_cache_stats(&zdbfs);

    zdbfs_debug("[+] fuse: cleaning environment\n");
    fuse_session_unmount(se);
    fuse_remove_signal_handlers(se);
    fuse_session_destroy(se);
    fuse_opt_free_args(&args);

    // free blocks and inodes cache
    zdbfs_init_free(&zdbfs, &fopts);

    // flag filesystem not in use anymore
    zdbfs_inode_init_release(&zdbfs);

    // disconnect redis
    zdbfs_zdb_free(&zdbfs);

    return ret;
}
