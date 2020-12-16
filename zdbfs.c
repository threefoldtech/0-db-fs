#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <errno.h>
#include <linux/fs.h>
#include <sys/epoll.h>
#include "zdbfs.h"
#include "zdb.h"
#include "inode.h"
#include "cache.h"

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
// #define volino

// WARNING: volino disabled for cache, this lead to
//          major leak

void __cleanup_inode(void *p) {
    zdb_inode_t *x = * (zdb_inode_t **) p;
    if(x == NULL)
        return;

    if(x->ino == 0)
        zdbfs_inode_free(x);

    // zdbfs_inode_free(* (zdb_inode_t **) p);
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
    zdbfs_debug(COLOR_RED "[-] %s: ino %u: %s\n" COLOR_RESET, caller, ino, strerror(err));
    fuse_reply_err(req, err);
}


//
// fuse syscall implementation
//
static void zdbfs_fuse_init(void *userdata, struct fuse_conn_info *conn) {
    (void) userdata;

    zdbfs_syscall("[+] syscall: init [%d]\n", conn->want);
}

static void zdbfs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    struct stat stbuf;
    volino zdb_inode_t *inode = NULL;
    (void) fi;

    zdbfs_syscall("[+] syscall: getattr: ino: %ld\n", ino);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, ENOENT, ino);

    zdbfs_inode_to_stat(&stbuf, inode, ino);

    fuse_reply_attr(req, &stbuf, ZDBFS_KERNEL_CACHE_TIME);
}

static void zdbfs_fuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    volino zdb_inode_t *inode = NULL;
    struct stat stbuf;
    (void) fi;

    zdbfs_syscall("[+] syscall: setattr: ino: %ld\n", ino);

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

    zdbfs_syscall("[+] syscall: lookup: parent: %ld, name: %s\n", parent, name);

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
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *create = NULL;
    uint32_t ino;

    zdbfs_syscall("[+] syscall: create: parent: %ld, name: %s\n", parent, name);

    if(!(inode = zdbfs_directory_fetch(req, parent)))
        return;

    // new file
    create = zdbfs_inode_new_file(req, mode);
    if((ino = zdbfs_inode_store_metadata(req, create, 0)) == 0)
        dies("create", "could not create inode");

    // update directory with new entry
    zdbfs_inode_dir_append(inode, ino, name);

    if(zdbfs_inode_store_metadata(req, inode, parent) != parent)
        dies("create", "could not update parent directory");

    zdbfs_inode_to_fuse_param(&e, create, ino);
    fuse_reply_create(req, &e, fi);
}

static void zdbfs_fuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    struct fuse_entry_param e;
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *newdir = NULL;

    zdbfs_syscall("[+] syscall: mkdir: parent: %ld, name: %s\n", parent, name);

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
    (void) fi;
    volino zdb_inode_t *inode = NULL;
    off_t limit = 0;

    zdbfs_syscall("[+] syscall: readdir: %lu: size: %lu, offset: %ld\n", ino, size, off);

    if(!(inode = zdbfs_directory_fetch(req, ino))) {
        printf("FAILED\n");
        return;
    }

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
        fuse_add_direntry(req, (char *) ptr, cursize, entry->name, &stbuf, i + 1);

        ptr += cursize;
    }

    fuse_reply_buf(req, buffer.buffer, buffer.length);

    free(buffer.buffer);
}

static void zdbfs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    volino zdb_inode_t *inode = NULL;

    zdbfs_syscall("[+] syscall: open: ino %lu: request\n", ino);

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
    (void) fi;
    volino zdb_inode_t *inode = NULL;
    size_t fetched = 0;
    char *buffer;

    zdbfs_syscall("[+] syscall: read: ino %lu: size %lu, off: %lu\n", ino, size, off);

    if(!(inode = zdbfs_inode_fetch(req, ino)))
        return zdbfs_fuse_error(req, EIO, ino);

    // zdbfs_inode_dump(inode);

    if(!(buffer = calloc(size, 1)))
        diep("read: malloc buffer");

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
            zdb_free(reply);
            break;
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
        zdb_free(reply);

        if(chunk == 0) {
            zdbfs_debug("[+] read: nothing more to read\n");
            break;
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

    fuse_reply_buf(req, buffer, fetched);

    free(buffer);
}

static void zdbfs_fuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void) fi;
    zdbfs_t *fs = fuse_req_userdata(req);
    volino zdb_inode_t *inode = NULL;
    zdb_reply_t *reply;
    size_t sent = 0;

    zdbfs_syscall("[+] syscall: write: ino %lu: size %lu, off: %lu\n", ino, size, off);

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

        // compute how many bytes to write _maximun_ on this chunk
        // this can be larger than blocksize
        size_t towrite = (size - sent > ZDBFS_BLOCK_SIZE) ? ZDBFS_BLOCK_SIZE : size - sent;

        // keep track of this chunk length
        size_t writepass = towrite;
        // const char *buffer = buf + sent;
        const char *buffer = fs->tmpblock;

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
                zdb_free(reply);
                return zdbfs_fuse_error(req, EINVAL, ino);
            }

            // if fetched block is larger than what we need to write
            // updating blocksize to read size
            if(reply->length > blocksize)
                blocksize = reply->length;

            // copying block from backend into temporarily buffer
            memcpy(fs->tmpblock, reply->value, reply->length);

            // merge existing block buffer with write chunk
            // memcpy(fs->tmpblock + alignment, buf + sent, writepass);

            // replace buffer pointer by temporarily buffer
            // buffer = fs->tmpblock;

            // FIXME
            zdb_free(reply);
        }

        zdbfs_debug("[+] write: writing %lu bytes (%lu / %lu, block: %u)\n", blocksize, sent, size, blockid);

        // merge existing block buffer with write chunk
        memcpy(fs->tmpblock + alignment, buf + sent, writepass);

        // send block to the backend, this can be a new block or an existing
        // block updated
        if((blockid = zdbfs_inode_block_store(req, inode, ino, block, buffer, blocksize)) == 0) {
            // dies("write", "cannot write block to backend");
            printf("inode store returned zero\n");
        }

        // jump to the next chunk to write
        sent += writepass;
    }

    if(off + size > inode->size)
        inode->size = off + size;

    zdbfs_debug("[+] write: all blocks written (%lu bytes)\n", sent);
    if(zdbfs_inode_store_metadata(req, inode, ino) == 0) {
        dies("write", "could not update inode blocks");
    }

    fuse_reply_write(req, sent);
}

static void zdbfs_fuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
    volino zdb_inode_t *newlink = NULL;
    volino zdb_inode_t *directory = NULL;
    uint32_t ino = 0;
    struct fuse_entry_param e;

    zdbfs_syscall("[+] syscall: symlink: ino %lu/%s -> %s\n", parent, name, link);

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
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *newdir = NULL;
    struct fuse_entry_param e;

    zdbfs_syscall("[+] syscall: link: ino %lu -> %lu, %s\n", ino, newparent, newname);

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
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *file = NULL;
    zdb_direntry_t *entry;

    //
    // FIXME: no forget support
    //
    zdbfs_syscall("[+] syscall: unlink: parent %lu, name: %s\n", parent, name);

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
    if(zdbfs_inode_unlink(req, file, entry->ino))
        return zdbfs_fuse_error(req, EIO, entry->ino);

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
    volino zdb_inode_t *inode = NULL;
    volino zdb_inode_t *target = NULL;

    //
    // FIXME: no forget support
    //
    zdbfs_syscall("[+] syscall: rmdir: parent %lu, name: %s\n", parent, name);

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

    zdbfs_syscall("[+] syscall: rename: %lu, name: %s -> name: %s\n", parent, name, newname);

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

        zdbfs_inode_unlink(req, existing, target->ino);

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
    volino zdb_inode_t *old = NULL;
    volino zdb_inode_t *new = NULL;
    volino zdb_inode_t *existing = NULL;
    uint32_t sourceino = 0;

    if(parent == newparent)
        return zdbfs_fuse_rename_same(req, parent, name, newname, flags);

    zdbfs_syscall("[+] syscall: rename: %lu, name: %s -> %lu, name: %s\n", parent, name, newparent, newname);

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

        zdbfs_inode_unlink(req, existing, nentry->ino);

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

    zdbfs_syscall("[+] syscall: flush: %lu\n", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    inocache_t *inocache;
    // zdbfs_t *fs = fuse_req_userdata(req);

    zdbfs_syscall("[+] syscall: release: %lu\n", ino);

    if(!(inocache = zdbfs_cache_get(req, ino))) {
        zdbfs_debug("[+] release: entry not found in cache, nothing to do\n");
        fuse_reply_err(req, 0);
        return;
    }

    // release
    zdbfs_cache_release(req, inocache);
    // zdbfs_inode_dump(inocache->inode);

    // zdbfs_inode_free(inode);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void) fi;
    (void) datasync;

    zdbfs_syscall("[+] syscall: fsync: %lu\n", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    zdbfs_syscall("[+] syscall: forget: %lu, nlookup: %lu\n", ino, nlookup);
    fuse_reply_none(req);
}

static void zdbfs_fuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;

    zdbfs_syscall("[+] syscall: opendir: %lu\n", ino);
    fuse_reply_open(req, fi);
}

static void zdbfs_fuse_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;

    zdbfs_syscall("[+] syscall: releasedir: %lu\n", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void) fi;
    (void) datasync;

    zdbfs_syscall("[+] syscall: fsyncdir: %lu\n", ino);
    fuse_reply_err(req, 0);
}

static void zdbfs_fuse_statfs(fuse_req_t req, fuse_ino_t ino) {
    (void) ino;

    // FIXME: hardcoded values
    struct statvfs vfs = {
        .f_bsize = ZDBFS_BLOCK_SIZE,
        .f_frsize = 1024,
        .f_blocks = 10 * 1024 * 1024,
        .f_bfree = 10 * 1024 * 1024,
        .f_bavail = 10 * 1024 * 1024,
        .f_files = 1,
        .f_ffree = 500,
        .f_favail = 1000,
        .f_fsid = 0,
        .f_flag = 0,
        .f_namemax = 255,
    };

    fuse_reply_statfs(req, &vfs);
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
        diep("epoll_create1");

    event.data.fd = ffd;
    event.events = EPOLLIN;

    // only watch for read event
    if(epoll_ctl(evfd, EPOLL_CTL_ADD, ffd, &event) < 0)
        diep("epoll_ctl");

    if(!(events = calloc(ZDBFS_EPOLL_MAXEVENTS, sizeof event)))
        diep("event: calloc");

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
        if(n == 0 || proceed > 32768) {
            size_t flushed = zdbfs_cache_sync(fs);

            if(flushed > 0)
                printf("[+] cache: flushed %lu inodes\n", flushed);

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
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config config;

    zdbfs_t zdbfs = {
        .mdctx = NULL,
        .datactx = NULL,
        .caching = 1,
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
    if(!(se = fuse_session_new(&args, &zdbfs_fuse_oper, sizeof(zdbfs_fuse_oper), &zdbfs)))
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
    if(!(zdbfs.tmpblock = malloc(ZDBFS_BLOCK_SIZE)))
        diep("cache: malloc: block");

    if(!(zdbfs.inocache = (inocache_t *) calloc(sizeof(inocache_t), ZDBFS_INOCACHE_LENGTH)))
        diep("cache: malloc: inocache");


    if(zdbfs.caching == 0)
        zdbfs_warning("[+] warning: cache disabled [%d]\n", zdbfs.caching);

    // if(opts.singlethread)
    zdbfs_success("[+] fuse: ready, waiting events: %s\n", opts.mountpoint);
    int ret = zdbfs_fuse_session_loop(se, &zdbfs, 1000);
    (void) config;

    // config.clone_fd = opts.clone_fd;
    // config.max_idle_threads = 10;
    // int ret = fuse_session_loop_mt(se, &config);

    printf("\n[+] fuse: stopping filesystem\n");

    printf("[+] cache: forcing cache flush\n");
    size_t flushed = zdbfs_cache_clean(&zdbfs);
    printf("[+] cache: flushed, %lu entries written\n", flushed);

    zdbfs_cache_stats(&zdbfs);

    zdbfs_debug("[+] fuse: cleaning environment\n");
    fuse_session_unmount(se);
    fuse_remove_signal_handlers(se);
    fuse_session_destroy(se);

    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    // free block cache
    free(zdbfs.tmpblock);
    free(zdbfs.inocache);

    // disconnect redis
    redisFree(zdbfs.mdctx);
    redisFree(zdbfs.datactx);

    return ret;
}
