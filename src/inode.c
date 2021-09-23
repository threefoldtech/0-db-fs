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
#include "init.h"
#include "zdb.h"
#include "inode.h"
#include "cache.h"
#include "system.h"

void zdbfs_inode_dump(zdb_inode_t *inode) {
    printf("[+] <<< inode dump\n");
    printf("[+] mode: %o\n", inode->mode);

    if(S_ISDIR(inode->mode))
        printf("[+] inode type: directory\n");

    if(S_ISCHR(inode->mode))
        printf("[+] inode type: character special\n");

    if(S_ISBLK(inode->mode))
        printf("[+] inode type: block special file\n");

    if(S_ISFIFO(inode->mode))
        printf("[+] inode type: fifo file\n");

    if(S_ISLNK(inode->mode))
        printf("[+] inode type: symbolic link\n");

    if(S_ISSOCK(inode->mode))
        printf("[+] inode type: unix socket\n");

    if(S_ISDIR(inode->mode)) {
        zdb_dir_root_t *root = zdbfs_inode_dir_root_get(inode);
        size_t dirtotal = 0;

        for(size_t d = 0; d < DIRLIST_SIZE; d++) {
            zdb_dir_t *dir = root->dirlist[d];

            if(dir == NULL)
                continue;

            printf("[+] directory dirlist %lu\n", d);
            printf("[+]   list length: %u\n", dir->length);

            for(size_t i = 0; i < dir->length; i++) {
                zdb_direntry_t *entry = dir->entries[i];
                printf("[+]   -- entry: %s [%lu]\n", entry->name, entry->ino);
                dirtotal += 1;
            }
        }

        printf("[+] directory total entries: %lu\n", dirtotal);
    }

    if(S_ISREG(inode->mode)) {
        printf("[+] inode type: regular file\n");

        zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);
        printf("[+] blocks length: %lu\n", blocks->length);

        for(size_t i = 0; i < blocks->length; i++)
            printf("[+] inode block [%lu]: %u\n", i, blocks->blocks[i]);
    }

    printf("[+] >>> inode dump\n");
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
    zdbfs_debug("[+] block: offset %ld => block %lu\n", off, block);
    return block;
}

void zdbfs_inode_block_set(zdb_inode_t *inode, size_t block, uint32_t blockid) {
    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);

    if(block + 1 > blocks->length) {
        size_t newlength = sizeof(zdb_blocks_t) + (sizeof(uint32_t) * (block + 1));

        // FIXME
        if(!(inode->extend[0] = realloc(blocks, newlength)))
            zdbfs_sysfatal("blocks: realloc");

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
    return sizeof(zdb_direntry_t) + entry->size + 1;
}

size_t zdbfs_inode_dir_size(zdb_dir_t *dir) {
    size_t length = sizeof(zdb_dir_header_t);

    for(size_t i = 0; i < dir->length; i++)
        length += zdbfs_direntry_size(dir->entries[i]);

    return length;
}

static zdb_dir_t *zdbfs_dir_resize(zdb_dir_t *dir, uint32_t length) {
    size_t dirsize = sizeof(zdb_direntry_t *) * length;

    if(!(dir->entries = realloc(dir->entries, dirsize)))
        zdbfs_sysfatal("inode: dir: append: realloc");

    dir->length = length;

    return dir;
}

size_t zdbfs_inode_file_size(zdb_inode_t *inode) {
    size_t length = sizeof(zdb_inode_t);
    length += sizeof(zdb_blocks_t);

    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(inode);
    length += blocks->length * ZDBFS_BLOCK_SIZE;

    return length;
}

zdb_dir_t *zdbfs_dir_new() {
    zdb_dir_t *dir;

    // initialize an empty directory in memory
    if(!(dir = calloc(sizeof(zdb_dir_t), 1)))
        zdbfs_sysfatal("inode: dir: new: malloc");

    return dir;
}

zdb_dir_root_t *zdbfs_dir_root_new(uint64_t parent) {
    zdb_dir_root_t *root;
    size_t index;

    if(!(root = calloc(sizeof(zdb_dir_root_t), 1)))
        zdbfs_sysfatal("inode: dir: root: new: malloc");

    index = zdbfs_inode_dirlist_id(".");
    root->dirlist[index] = zdbfs_dir_new();
    root->dirlist[index] = zdbfs_dir_append(root->dirlist[index], zdbfs_direntry_new(parent, "."));

    index = zdbfs_inode_dirlist_id("..");
    root->dirlist[index] = zdbfs_dir_new();
    root->dirlist[index] = zdbfs_dir_append(root->dirlist[index], zdbfs_direntry_new(parent, ".."));

    return root;
}

zdb_inode_t *zdbfs_inode_new_dir(uint64_t parent, uint32_t mode) {
    zdb_dir_root_t *dir;
    zdb_inode_t *inode;

    // create empty directory
    dir = zdbfs_dir_root_new(parent);

    // create empty inode
    if(!(inode = calloc(sizeof(zdb_inode_t) + sizeof(zdb_dir_root_t *), 1)))
        zdbfs_sysfatal("inode: newdir: calloc");

    // set inode and link directory to it
    inode->mode = S_IFDIR | mode;
    inode->ctime = time(NULL);
    inode->atime = inode->ctime;
    inode->mtime = inode->ctime;

    zdbfs_inode_dir_root_set(inode, dir);

    return inode;
}

//
// lookup implementation
//
// binary search files inside directory files list
static ssize_t zdbfs_inode_lookup_direntry_bi(zdb_dir_t *dir, const char *name) {
    int low = 0;
    int high = dir->length - 1;
    int compare;

    while(low <= high) {
        int mid = low + (high - low) / 2;

        if((compare = strcmp(name, dir->entries[mid]->name)) == 0)
            return mid;

        if(compare < 0)
            high = mid - 1;
        else
            low = mid + 1;
    }

    return -1;
}

// compute insertion index with binary search
static int zdbfs_inode_dir_append_index(zdb_dir_t *dir, int len, char *name) {
    int low = 0;
    int high = len;

    while(low < high) {
        int mid = (low + high) / 2;

        if(strcmp(name, dir->entries[mid]->name) > 0)
            low = mid + 1;
        else
            high = mid;
    }

    return low;
}

//
// deserializer
//
static zdb_dir_t *zdbfs_inode_deserialize_dir_entries(uint8_t *buffer, size_t length) {
    zdb_dir_header_t *header;
    zdb_dir_t *dir;

    header = (zdb_dir_header_t *) buffer;
    // zdbfs_system_fulldump(buffer, length);

    if(!(dir = calloc(sizeof(zdb_dir_t), 1)))
        zdbfs_sysfatal("inode: deserialize: dir entries: calloc");

    if(!(dir->entries = calloc(sizeof(zdb_direntry_t *), header->length)))
        zdbfs_sysfatal("inode: deserialize: dir entries list: calloc");

    uint8_t *ptr = buffer + sizeof(zdb_dir_header_t);

    // zdbfs_system_fulldump(ptr, length - sizeof(zdb_dir_header_t));
    // printf("DESERIALIZE %u ENTRIES\n", header->length);

    for(size_t i = 0; i < header->length; i++) {
        zdb_direntry_t *entry = (zdb_direntry_t *) ptr;
        size_t entlen = zdbfs_direntry_size(entry);

        dir->entries[i] = zdbfs_direntry_new(entry->ino, entry->name);
        dir->length += 1;

        // printf("<-> %lu | %s\n", dir->entries[i]->ino, dir->entries[i]->name);
        ptr += entlen;
    }

    return dir;
}

zdb_dir_t *zdbfs_inode_fetch_dir_entries(zdb_t *backend, uint64_t id) {
    zdb_reply_t *reply;
    zdb_dir_t *dir;

    if(!(reply = zdb_get(backend, id)))
        return NULL;

    if(!(dir = zdbfs_inode_deserialize_dir_entries(reply->value, reply->length))) {
        zdbfs_zdb_reply_free(reply);
        return NULL;
    }

    zdbfs_zdb_reply_free(reply);

    // link dirlist entry id
    dir->ino = id;

    return dir;
}

zdb_inode_t *zdbfs_inode_deserialize_dir(zdb_t *backend, zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    (void) length;
    zdb_dir_root_serial_t *serial = (zdb_dir_root_serial_t *) (buffer + sizeof(zdb_inode_t));
    zdb_dir_root_t *root;

    if(!(root = calloc(sizeof(zdb_dir_root_t), 1)))
        zdbfs_sysfatal("inode: deserialize: dir root: calloc");

    // link root list to inode extend
    inode->extend[0] = root;

    for(size_t i = 0; i < DIRLIST_SIZE; i++) {
        if(serial->dirlist[i] == 0x4242424242424242)
            continue;

        zdb_dir_t *dirlist;

        // printf("<< %lx\n", serial->dirlist[i]);
        // printf("FETCHING dirlist %lx\n", serial->dirlist[i]);

        if(!(dirlist = zdbfs_inode_fetch_dir_entries(backend, serial->dirlist[i]))) {
            zdbfs_critical("[-] inode: deserializer: could not fetch dirlist id %lu\n", serial->dirlist[i]);
            continue;
        }

        root->dirlist[i] = dirlist;
    }

    // zdbfs_inode_dump(inode);

    return inode;
}

zdb_inode_t *zdbfs_inode_deserialize_file(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    zdb_blocks_t *blocks = (zdb_blocks_t *) (buffer + sizeof(zdb_inode_t));

    if(!(inode->extend[0] = malloc(length - sizeof(zdb_inode_t))))
        zdbfs_sysfatal("inode: deserialize: file: malloc");

    memcpy(inode->extend[0], blocks, length - sizeof(zdb_inode_t));

    return inode;
}

zdb_inode_t *zdbfs_inode_deserialize_symlink(zdb_inode_t *inode, uint8_t *buffer, size_t length) {
    char *link = (char *) (buffer + sizeof(zdb_inode_t));

    if(!(inode->extend[0] = malloc(length - sizeof(zdb_inode_t))))
        zdbfs_sysfatal("inode: deserialize: symlink: malloc");

    memcpy(inode->extend[0], link, length - sizeof(zdb_inode_t));

    return inode;
}

zdb_inode_t *zdbfs_inode_deserialize(zdb_t *backend, uint8_t *buffer, size_t length) {
    zdb_inode_t *inode;

    if(length < sizeof(zdb_inode_t))
        dies("deserialize", "wrong size from db");

    // allocate inode struct plus one pointer for extend
    if(!(inode = malloc(sizeof(zdb_inode_t) + sizeof(void *))))
        zdbfs_sysfatal("inode: deserialize: inode: malloc");

    // copy inode from buffer to inode, as it
    memcpy(inode, buffer, sizeof(zdb_inode_t));
    inode->ino = 0; // FIXME: cache fix

    // nothing more to do if it's not a directory
    if(S_ISLNK(inode->mode))
        return zdbfs_inode_deserialize_symlink(inode, buffer, length);

    // handling directory
    if(!S_ISDIR(inode->mode))
        return zdbfs_inode_deserialize_file(inode, buffer, length);

    // handling everything else as file
    return zdbfs_inode_deserialize_dir(backend, inode, buffer, length);
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
        zdbfs_sysfatal("inode: serialize: file: malloc");

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
        zdbfs_sysfatal("inode: serialize: symlink: malloc");

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

zdb_dir_t *zdbfs_inode_serialize_dir_entries(zdb_t *backend, zdb_dir_t *dir) {
    size_t inolen = zdbfs_inode_dir_size(dir);
    uint8_t *serial;

    if(!(serial = calloc(inolen, 1)))
        zdbfs_sysfatal("inode: serialize: dir entries: malloc");

    // copy original content of zdb_dir_t header
    memcpy(serial, dir, sizeof(zdb_dir_header_t));
    uint8_t *ptr = serial + sizeof(zdb_dir_header_t);

    // copying content of each direntries
    for(size_t i = 0; i < dir->length; i++) {
        zdb_direntry_t *entry = dir->entries[i];
        // zdbfs_debug("[+] inode: serialier: direntry: %s\n", entry->name);

        size_t length = zdbfs_direntry_size(entry);

        memcpy(ptr, entry, length);
        ptr += length;
    }

    // zdbfs_system_fulldump(serial, inolen);

    uint64_t key;
    if((key = zdb_set(backend, dir->ino, serial, inolen)) != dir->ino) {
        zdbfs_critical("could not update directory list id %lu", dir->ino);
        return NULL;
    }

    free(serial);

    return dir;
}

buffer_t zdbfs_inode_serialize_dir(zdb_t *backend, zdb_inode_t *inode) {
    buffer_t buffer;
    zdb_inode_t *serial;
    zdb_dir_root_t *dir = zdbfs_inode_dir_root_get(inode);
    size_t inolen = sizeof(zdb_inode_t) + sizeof(zdb_dir_root_serial_t);

    if(!(serial = malloc(inolen)))
        zdbfs_sysfatal("inode: serialize: dir: malloc");

    // FIXME debug
    memset(serial, 0x42, inolen);

    // first copy the inode data
    memcpy(serial, inode, sizeof(zdb_inode_t));

    // point serial root to buffer
    zdb_dir_root_serial_t *serialist = (zdb_dir_root_serial_t *) &serial->extend[0];

    // building the list map based on memory representation
    // each list entry have an inode number stored, which can
    // be zero (not yet defined) or something, if it's set to
    // something that mean it's already in the backend and can
    // be updated
    //
    // basically that map will match between list id and list
    // entry in the backend (serialized):
    //   list 0: 0x00  --  not set
    //   list 1: 0x00  --  not set
    //   list 2: 0x87  --  entry 0x87 in the backend
    //   list 3: 0xaf  --  entry 0xaf in the backend
    //   list 4: 0x00  --  not set
    //   ...
    //
    // in memory, or the list is NULL (not yet used), or allocated
    // and allocation contains inode number (zero or defined)
    for(size_t i = 0; i < DIRLIST_SIZE; i++) {
        zdb_dir_t *dirlist;

        if((dirlist = dir->dirlist[i]) == NULL)
            continue;

        zdbfs_debug("[+] inode: serializing directory list: %lu\n", i);

        if(dirlist->ino == 0) {
            zdbfs_debug("[+] inode: serializer: no ino set yet for dirlist, creating a new one\n");
            uint64_t key = zdb_set(backend, 0, "L", 1);

            // printf("key attributed = %lu\n", key);
            dirlist->ino = key;
        }

        // set inode id to serialized buffer
        serialist->dirlist[i] = dirlist->ino;

        // push list to backend (won't be updated if it's the same)
        if(!zdbfs_inode_serialize_dir_entries(backend, dirlist))
            zdbfs_critical("inode: serializer: dir: list %lu serialization failed", i);
    }

    // zdbfs_system_fulldump(serial, inolen);

    buffer.buffer = serial;
    buffer.length = inolen;

    return buffer;

}

buffer_t zdbfs_inode_serialize(zdb_t *backend, zdb_inode_t *inode) {
    if(S_ISDIR(inode->mode))
        return zdbfs_inode_serialize_dir(backend, inode);

    if(S_ISLNK(inode->mode))
        return zdbfs_inode_serialize_symlink(inode);

    return zdbfs_inode_serialize_file(inode);
}



zdb_direntry_t *zdbfs_direntry_new(uint64_t ino, const char *name) {
    zdb_direntry_t *entry;
    size_t namelen = strlen(name);

    if(!(entry = malloc(sizeof(zdb_direntry_t) + namelen + 1)))
        zdbfs_sysfatal("inode: direntry: new: malloc");

    entry->ino = ino;
    entry->size = namelen;
    strcpy(entry->name, name);

    return entry;
}

static zdb_dir_t *zdbfs_dir_append_to_empty(zdb_dir_t *dir, zdb_direntry_t *entry) {
    // set initial size to 1 and assign entry
    dir = zdbfs_dir_resize(dir, 1);
    dir->entries[0] = entry;

    return dir;
}

zdb_dir_t *zdbfs_dir_append(zdb_dir_t *dir, zdb_direntry_t *entry) {
    // special case if zdb_dir_t is empty
    if(dir->length == 0)
        return zdbfs_dir_append_to_empty(dir, entry);

    // resize directory (grow up)
    zdbfs_dir_resize(dir, dir->length + 1);

    // compute index where to insert (ordered) entry
    ssize_t index = zdbfs_inode_dir_append_index(dir, dir->length - 1, entry->name);
    zdbfs_debug("[+] inode: dir: append: new index: %ld\n", index);

    // compute how much we need to shift
    size_t length = (dir->length - index - 1) * sizeof(zdb_direntry_t *);

    // shift array to get new free spot
    memmove(dir->entries + index + 1, dir->entries + index, length);

    // insert new element at the right location
    dir->entries[index] = entry;

    return dir;
}

zdb_dir_t *zdbfs_inode_dir_append(zdb_inode_t *inode, uint64_t ino, const char *name) {
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode, name);
    zdb_direntry_t *entry = zdbfs_direntry_new(ino, name);

    // update payload
    zdbfs_dir_append(dir, entry);

    // update inode size
    inode->size += zdbfs_direntry_size(entry);

    return dir;
}

static ssize_t zdbfs_inode_lookup_direntry_index(zdb_inode_t *inode, const char *name) {
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode, name);
    return zdbfs_inode_lookup_direntry_bi(dir, name);
}

zdb_direntry_t *zdbfs_inode_lookup_direntry(zdb_inode_t *inode, const char *name) {
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode, name);
    ssize_t index = zdbfs_inode_lookup_direntry_bi(dir, name);

    if(index < 0)
        return NULL;

    return dir->entries[index];
}

int zdbfs_inode_remove_entry(zdb_inode_t *inode, const char *name) {
    zdb_dir_t *dir = zdbfs_inode_dir_get(inode, name);
    ssize_t index;

    // lookup for entry index
    if((index = zdbfs_inode_lookup_direntry_index(inode, name)) < 0)
        return 1;

    zdbfs_debug("[+] inode: remove entry: entry found (index: %ld), deleting\n", index);

    // update inode size
    zdb_direntry_t *entry = dir->entries[index];
    inode->size -= zdbfs_direntry_size(entry);

    // cleanup that entry
    free(dir->entries[index]);

    // compute nex array size
    size_t length = (dir->length - index - 1) * sizeof(zdb_direntry_t *);
    zdbfs_debug("[+] inode: remove entry: shifting %lu bytes\n", length);

    // shift array to the left
    memmove(dir->entries + index, dir->entries + index + 1, length);
    dir->length -= 1;

    return 0;
}

//
// accessors
//
zdb_dir_root_t *zdbfs_inode_dir_root_get(zdb_inode_t *inode) {
    return inode->extend[0];
}

zdb_dir_t *zdbfs_inode_dir_get(zdb_inode_t *inode, const char *name) {
    // compute dirlist index from name
    size_t index = zdbfs_inode_dirlist_id(name);

    // grab root dirlist from inode
    zdb_dir_root_t *root = zdbfs_inode_dir_root_get(inode);

    if(root->dirlist[index] == NULL) {
        if(!(root->dirlist[index] = zdbfs_dir_new()))
            return NULL;
    }

    // match on the correct dirlist based on index
    return root->dirlist[index];
}

zdb_dir_root_t *zdbfs_inode_dir_root_set(zdb_inode_t *inode, zdb_dir_root_t *root) {
    inode->extend[0] = root;
    return root;
}

zdb_blocks_t *zdbfs_inode_blocks_get(zdb_inode_t *inode) {
    return inode->extend[0];
}

void zdbfs_inode_to_fuse_param(struct fuse_entry_param *param, zdb_inode_t *inode, uint64_t ino) {
    memset(param, 0, sizeof(struct fuse_entry_param));

    param->ino = ino;
    param->attr_timeout = ZDBFS_KERNEL_CACHE_TIME;
    param->entry_timeout = ZDBFS_KERNEL_CACHE_TIME;

    zdbfs_inode_to_stat(&param->attr, inode, ino);
}

void zdbfs_inode_to_stat(struct stat *st, zdb_inode_t *inode, uint64_t ino) {
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
    st->st_blksize = 0;
    st->st_rdev = 0;
    st->st_dev = 0;
}

void zdbfs_dir_free(zdb_dir_t *dir) {
    for(size_t i = 0; i < dir->length; i++)
        free(dir->entries[i]);

    free(dir->entries);
    free(dir);
}

void zdbfs_dir_root_free(zdb_dir_root_t *root) {
    for(size_t d = 0; d < DIRLIST_SIZE; d++) {
        // free dirlist if existing
        if(root->dirlist[d] != NULL)
            zdbfs_dir_free(root->dirlist[d]);
    }

    free(root);
}

void zdbfs_inode_free(zdb_inode_t *inode) {
    // do nothing on null inode
    if(!inode)
        return;

    if(S_ISDIR(inode->mode)) {
        // free directory entries
        zdbfs_dir_root_free(inode->extend[0]);
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

zdb_inode_t *zdbfs_inode_fetch_backend(fuse_req_t req, fuse_ino_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    zdb_reply_t *reply;

    zdbfs_debug("[+] inode: backend fetch: %ld\n", ino);

    // if we don't have any reply from zdb, entry doesn't exists
    if(!(reply = zdb_get(fs->metactx, ino))) {
        zdbfs_debug("[+] inode: fetch: %lu: not found\n", ino);
        // fuse_reply_err(req, ENOENT);
        return NULL;
    }

    zdb_inode_t *inode = zdbfs_inode_deserialize(fs->metactx, reply->value, reply->length);
    zdbfs_zdb_reply_free(reply);

    return inode;
}

zdb_inode_t *zdbfs_inode_fetch(fuse_req_t req, fuse_ino_t ino) {
    inocache_t *inocache;
    zdb_inode_t *inode;

    // cache hit
    if((inocache = zdbfs_cache_get(req, ino)))
        return inocache->inode;

    // cache miss
    if(!(inode = zdbfs_inode_fetch_backend(req, ino)))
        return NULL;

    // add entry to cache
    // zdbfs_cache_add(req, ino, inode);

    return inode;
}

zdb_inode_t *zdbfs_directory_fetch(fuse_req_t req, fuse_ino_t ino) {
    zdb_inode_t *inode;

    zdbfs_debug("[+] directory: fetch: %ld\n", ino);

    if(!(inode = zdbfs_inode_fetch(req, ino))) {
        fuse_reply_err(req, ENOENT);
        return NULL;
    }

    // checking if this inode is a directory
    if(!S_ISDIR(inode->mode)) {
        zdbfs_debug("[-] directory: %lu: not a directory\n", ino);
        fuse_reply_err(req, ENOTDIR);
        return NULL;
    }

    return inode;
}

uint64_t zdbfs_inode_store_backend(zdb_t *backend, zdb_inode_t *inode, uint64_t ino) {
    buffer_t save = zdbfs_inode_serialize(backend, inode);
    uint64_t inoret;

    inoret = zdb_set(backend, ino, save.buffer, save.length);

    // returns zero
    if(inoret == 0) {
        fprintf(stderr, "[-] zdbfs: store inode: failed\n");
        ino = 0;
    }

    free(save.buffer);

    return inoret;
}

uint64_t zdbfs_inode_store_metadata(fuse_req_t req, zdb_inode_t *inode, uint64_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    inocache_t *inocache;

    // if ino is zero, force metadata write, we don't
    // know inoid yet, we need to get one
    if(ino == 0) {
        uint64_t key = zdbfs_inode_store_backend(fs->metactx, inode, ino);
        if(key > 0)
            zdbfs_cache_add(req, key, inode);

        return key;
    }

    /*
    // if entry is not yet in cache, pushing metadata to
    // the backend
    if(!(inocache = zdbfs_cache_get(req, ino)))
        return zdbfs_inode_store_backend(fs->mdctx, inode, ino);
    */

    if(!(inocache = zdbfs_cache_get(req, ino))) {
        zdbfs_debug("[+] inode: write request for not cached inode, adding: %lu\n", ino);
        if(!zdbfs_cache_add(req, ino, inode)) {
            // cache full, force metadata push
            zdbfs_debug("[+] inode: metadata: store: cache not available, flushing\n");
            return zdbfs_inode_store_backend(fs->metactx, inode, ino);
        }
    }


    // entry in cache, delaying write
    zdbfs_debug("[+] inode: write delayed, item in cache\n");
    return ino;
}

uint64_t zdbfs_inode_store_data(fuse_req_t req, zdb_inode_t *inode, uint64_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    return zdbfs_inode_store_backend(fs->datactx, inode, ino);
}


//
// regular files
//
zdb_inode_t *zdbfs_inode_new_file(fuse_req_t req, uint32_t mode) {
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    zdb_inode_t *create;

    if(!(create = calloc(sizeof(zdb_inode_t) + sizeof(zdb_blocks_t *), 1)))
        zdbfs_sysfatal("inode: file: new: malloc");

    create->mode = S_IFREG | mode;
    create->ctime = time(NULL);
    create->atime = create->ctime;
    create->mtime = create->ctime;
    create->uid = ctx->uid;
    create->gid = ctx->gid;
    create->size = 0;
    create->links = 1;

    if(!(create->extend[0] = calloc(sizeof(zdb_blocks_t), 1)))
        zdbfs_sysfatal("inode: file: new: blocklist: calloc");

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
        zdbfs_sysfatal("inode: symlink: new: calloc");

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
        zdbfs_sysfatal("inode: symlink: new: strdup");

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

        if(blockid == 0) {
            zdbfs_debug("[+] inode: delete: skipping block %lu (not set)\n", block);
            continue;
        }

        zdbfs_debug("[+] inode: delete: block %lu [%u]\n", block, blockid);

        if(zdb_del(fs->datactx, blockid) != 0)
            return 1;

        // invalidate deleted block
        blocks->blocks[block] = 0;
    }

    return 0;
}

// remove one link of the given inode
// returns 0 if unlink succeed
//         1 on error
//         2 on reference decremented
int zdbfs_inode_unlink(fuse_req_t req, zdb_inode_t *file, uint64_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);
    inocache_t *cache;

    // decrease amount of links
    file->links -= 1;

    // check if inode is not linked on the filesystem
    if(file->links == 0) {
        if(S_ISREG(file->mode)) {
            // delete regular file blocks
            zdbfs_inode_blocks_remove(req, file);
        }

        // delete inode itself
        if(zdb_del(fs->metactx, ino) != 0)
            return 1;

        // invalidate cache if any
        if((cache = zdbfs_cache_get(req, ino))) {
            zdbfs_cache_drop(req, cache);
            // returns zero if cache cleaned
            // this mean inode shound not be freed
            // a second time later
            return 0;
        }

    } else {
        // save updated links
        if(zdbfs_inode_store_metadata(req, file, ino) != ino)
            return 1;
    }

    // link updated and metadata stored correctly
    // nothing more to do
    return 2;
}

zdb_reply_t *zdbfs_inode_block_fetch(fuse_req_t req, zdb_inode_t *file, uint64_t ino, uint32_t block) {
    zdbfs_t *fs = fuse_req_userdata(req);
    zdb_blocks_t *blocks = zdbfs_inode_blocks_get(file);
    uint32_t blockid = blocks->blocks[block];
    zdb_reply_t *reply;
    inocache_t *cache;

    zdbfs_debug("[+] inode: block fetch: request block %u [id %u]\n", block, blockid);

    // check cache first
    if((cache = zdbfs_cache_get(req, ino))) {
        blockcache_t *blc;

        if((blc = zdbfs_cache_block_get(req, cache, block))) {
            if(!(reply = malloc(sizeof(zdb_reply_t))))
                zdbfs_sysfatal("inode: block fetch: malloc");

            zdbfs_debug("[+] block: cache hit\n");
            reply->rreply = NULL;

            if(!(reply->value = malloc(blc->blocksize)))
                zdbfs_sysfatal("inode: cache duplicate block: malloc");

            memcpy(reply->value, blc->data, blc->blocksize);
            reply->length = blc->blocksize;

            return reply;
        }

        zdbfs_debug("[+] block: cache miss, but inode in cache\n");
    }

    if(!(reply = zdb_get(fs->datactx, blockid))) {
        // return zdbfs_fuse_error(req, EIO, ino);
        return NULL;
    }

    return reply;
}

uint32_t zdbfs_inode_block_store(fuse_req_t req, zdb_inode_t *inode, uint64_t ino, uint32_t block, const char *buffer, size_t buflen) {
    zdbfs_t *fs = fuse_req_userdata(req);

    uint32_t blockid = zdbfs_inode_block_get(inode, block);
    zdbfs_debug("[+] inode: write block request: block %u\n", block);

    inocache_t *cache;
    if(!(cache = zdbfs_cache_get(req, ino))) {
        zdbfs_debug("[+] inode: block: store: inode not in cache, direct write\n");

        // no cache available, force flush
        if((blockid = zdb_set(fs->datactx, blockid, buffer, buflen)) == 0)
            return 0;

        // force block update
        //
        // update inode blocklist with this block
        // it's possible this block was already on the list
        // this will just set it again
        zdbfs_inode_block_set(inode, block, blockid);
        return blockid;
    }

    blockcache_t *blc;

    if(!(blc = zdbfs_cache_block_get(req, cache, block))) {
        zdbfs_debug("[+] block: store: add new block in cache\n");

        /*
        uint32_t saved = zdbfs_inode_block_get(inode, cache->blockidx);
        if((saved = zdb_set(fs->datactx, saved, cache->block, cache->blocksize)) == 0) {
            dies("write", "cannot write block to backend");
        }

        // update block list
        zdbfs_inode_block_set(inode, block, saved);

        free(cache->block);
        cache->block = NULL;
        cache->blocksize = 0;
        */

        if(!(blc = zdbfs_cache_block_add(req, cache, block)))
            return 0;
    }

    // at this point, we are sure block is available
    // - zdbfs_cache_block_add pushed a new one, fresh available
    // - zdbfs_cache_block_get got an existing one, restored if offloaded
    zdbfs_debug("[+] block: store: update block cache content\n");
    zdbfs_cache_block_update(blc, buffer, buflen);

    if(blockid == 0) {
        // attributing a blockid to that block
        if((blockid = zdb_set(fs->datactx, 0, "", 0)) == 0)
            return 0;

        zdbfs_debug("[+] block: store: new blockid: %u\n", blockid);
    }

    // request update blockslist at least to grow the
    // list if this id was not set yet, even if block
    // is in cache and not assigned yet
    zdbfs_inode_block_set(inode, block, blockid);

    return blockid;
}

// FIXME: maybe try to optimize this
size_t zdbfs_inode_dirlist_id(const char *name) {
    size_t acc = 0;
    size_t len = strlen(name);

    for(size_t i = 0; i < len; i++)
        acc += name[i];

    // printf(">> %lu\n", acc % DIRLIST_SIZE);
    return acc % DIRLIST_SIZE;
}

static int zdbfs_header_check(uint8_t *buffer, size_t bufsize, char *magic) {
    zdbfs_header_t source;

    // if we don't have enough data for magic and version
    // for sure it's invalid
    if(bufsize < sizeof(source.magic) + sizeof(source.version)) {
        printf(">> not enough data for our header basic\n");
        return 1;
    }

    // copy magic and version from buffer
    memcpy(source.magic, buffer, sizeof(source.magic));
    memcpy(&source.version, buffer + sizeof(source.magic), sizeof(source.version));

    if(strncmp(source.magic, magic, strlen(magic)) != 0) {
        zdbfs_critical("header: invalid magic [%*s / %s]", (int) sizeof(source.magic), source.magic, magic);
        return 1;
    }

    if(source.version != ZDBFS_INTERNAL_VERSION) {
        zdbfs_critical("unexpected version from header [%u / %u]\n", source.version, ZDBFS_INTERNAL_VERSION);
        return 1;
    }

    zdbfs_debug("[+] filesystem: header: basic information valid\n");

    return 0;
}

static int zdbfs_inode_prepare_namespace(zdb_t *backend, zdbfs_header_t *header, char *magic) {
    uint64_t response;

    // create initial entry
    memcpy(header->magic, magic, sizeof(header->magic));

    // set initial entry
    if((response = zdb_set_initial(backend, header, sizeof(zdbfs_header_t), 0) != 0)) {
        char replied[32];
        sprintf(replied, "0x%lx", response);

        zdbfs_critical("initializer: initializing namespace magic <%s> failed\n", magic);
        dies("initializer: initial id mismatch (expected 0x00)", replied);
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
int zdbfs_inode_init(zdbfs_t *fs) {
    zdb_reply_t *reply;
    zdbfs_header_t header = {
        .version = ZDBFS_INTERNAL_VERSION,
        // .flags = ZDBFS_FLAGS_IN_USE,
        .flags = 0,
        .size = fs->fssize,
    };

    zdbfs_debug("[+] filesystem: checking backend\n");

    // check for zdb compatibility
    zdb_info_t *info;
    if(!(info = zdb_info(fs->metactx)))
        zdbfs_critical("cannot fetch zdb server information: %s", "error");

    if(info->seqsize != 8) {
        zdbfs_critical("incompatible version of 0-db: %s", "v2 with 64 bits keys required");
        exit(EXIT_FAILURE);
    }

    free(info);

    // checking if metadata entry (inode) 0 exists
    if((reply = zdb_get(fs->metactx, 0))) {
        if(zdbfs_header_check(reply->value, reply->length, "ZDBFSM") == 1) {
            zdbfs_critical("invalid header: %s", "metadata");
            return 1;
        }

        memcpy(&header, reply->value, sizeof(header));

        // we only check for metadata in use flag
        if(header.flags & ZDBFS_FLAGS_IN_USE) {
            zdbfs_debug("[-] filesystem: flag already in use set (ignore for now)\n");
            return 1;
        }

        zdbfs_debug("[+] filesystem: metadata contains a valid filesystem\n");
        zdbfs_zdb_reply_free(reply);

    } else {
        zdbfs_debug("[+] filesystem: creating metadata header\n");
        zdbfs_inode_prepare_namespace(fs->metactx, &header, "ZDBFSM");
    }


    //
    // create initial root directory (if not there)
    //
    if(!(reply = zdb_get(fs->metactx, 1))) {
        uint64_t id;

        zdbfs_debug("[+] filesystem: creating root directory\n");

        zdb_inode_t *inode = zdbfs_inode_new_dir(1, 0755);

        // create fake object to register id 1 in the backend
        // otherwise directory entries will takes entry 1 first
        if((id = zdb_set(fs->metactx, 0, "X", 1)) != 1)
            dies("could not create root entry in the backend", "initial");

        // save root entry in the backend
        if(zdbfs_inode_store_backend(fs->metactx, inode, 1) != 1)
            dies("could not create root directory", "initial");

        zdbfs_inode_free(inode);

    } else {
        zdbfs_debug("[+] filesystem: metadata already contains a valid root directory\n");
        zdbfs_zdb_reply_free(reply);
    }

    //
    // create initial block
    //
    if((reply = zdb_get(fs->datactx, 0))) {
        if(zdbfs_header_check(reply->value, reply->length, "ZDBFSD") == 1) {
            zdbfs_critical("invalid header: %s", "data blocks");
            return 1;
        }

        zdbfs_debug("[+] filesystem: data contains a valid filesystem\n");
        zdbfs_zdb_reply_free(reply);

    } else {
        zdbfs_debug("[+] filesystem: creating data blocks header\n");
        zdbfs_inode_prepare_namespace(fs->datactx, &header, "ZDBFSD");
    }

    // checking if temporary namespace 0 exists
    if((reply = zdb_get(fs->tempctx, 0))) {
        if(zdbfs_header_check(reply->value, reply->length, "ZDBFST") == 1) {
            zdbfs_critical("invalid header: %s", "temporary");
            return 1;
        }

        zdbfs_debug("[+] filesystem: temporary namespace contains a valid filesystem\n");
        zdbfs_zdb_reply_free(reply);

    } else {
        zdbfs_debug("[+] filesystem: creating temporary namespace header\n");
        zdbfs_inode_prepare_namespace(fs->tempctx, &header, "ZDBFST");
    }


    return 0;
}

int zdbfs_inode_init_release(zdbfs_t *fs) {
    zdbfs_header_t header;
    zdb_reply_t *reply;
    uint64_t response;

    zdbfs_debug("[+] filesystem: release in-use flag\n");

    if(!(reply = zdb_get(fs->metactx, 0))) {
        zdbfs_error("[-] filesystem: release: %s\n", "could not fetch header entry");
        return 1;
    }

    if(reply->length != sizeof(zdbfs_header_t)) {
        zdbfs_error("[-] filesystem: release: %s\n", "wrong header size");
        return 1;
    }

    memcpy(&header, reply->value, sizeof(header));

    // drop in use flags
    header.flags &= ~ZDBFS_FLAGS_IN_USE;

    if((response = zdb_set_initial(fs->metactx, &header, sizeof(zdbfs_header_t), 1)) != 0) {
        zdbfs_error("filesystem: release: %s\n", "could not update header entry");
    }

    zdbfs_zdb_reply_free(reply);

    return 0;
}

// TODO: improve. this is really dirty, but only used for log
//
//       this can reduce performance due to massive query just
//       for logging
//
//       this function does a reverse lookup based from an inode
//       to build the full path, inode (target) needs to be a directory
//
//       there is no way to know from an inode file, it's path, this could
//       be anything since hardlinks points to same inode etc.
char *zdbfs_inode_resolv(fuse_req_t req, fuse_ino_t target, const char *name) {
    char **paths = calloc(sizeof(char *), 256);
    int index = 1;
    fuse_ino_t parent = target;

    if(target == 1)
        return strdup("/");

    while(target > 1) {
        zdb_inode_t *inode = NULL;

        if(!(inode = zdbfs_inode_fetch(req, parent))) {
            zdbfs_debug("[-] resolv: could not fetch inode %lu, stopping\n", parent);
            free(paths);
            return strdup("");
        }

        // checking if this inode is a directory
        if(!S_ISDIR(inode->mode)) {
            zdbfs_debug("[-] resolve: %lu: not a directory, skipping\n", parent);
            // zdbfs_inode_free(inode);
            free(paths);
            return strdup("");
        }

        zdb_dir_t *dir = zdbfs_inode_dir_get(inode, name);

        for(uint32_t i = 0; i < dir->length; i++) {
            if(dir->entries[i]->ino == target) {
                paths[index++] = strdup(dir->entries[i]->name);
                target = parent;
                break;
            }
        }

        parent = dir->entries[0]->ino;
        // zdbfs_inode_free(inode);
    }

    char *path = calloc(sizeof(char), 1024);
    int len = 0;

    for(int i = index - 1; i > 0; i--) {
        len += sprintf(path + len, "/%s", paths[i]);
        free(paths[i]);
    }

    if(name)
        sprintf(path + len, "/%s", name);

    free(paths);

    return path;
}

