#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <time.h>
#include "zdbfs.h"
#include "inode.h"
#include "cache.h"

#define ZDBFS_CACHE_ENABLED

#if 0
void zdbfs_cache_dump(fuse_req_t req) {
    zdbfs_t *fs = fuse_req_userdata(req);

    for(size_t i = 0; i < INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];
        if(!cache->inode)
            continue;

        printf(">> cache %3lu: %c [%lu] -- %lu\n", i, S_ISDIR(cache->inode->mode) ? 'D' : 'X', cache->ref, cache->inode->size);
    }
}
#endif

//
// cache system
//
inocache_t *zdbfs_cache_get(fuse_req_t req, uint32_t ino) {
#ifndef ZDBFS_CACHE_ENABLED
    (void) req;
    (void) ino;
#else
    zdbfs_t *fs = fuse_req_userdata(req);
    zdbfs_lowdebug("[+] cache: lookup inode: %u\n", ino);

    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        if(cache->inoid == ino) {
            zdbfs_lowdebug("[+] cache: hit inode: %u\n", ino);

            // if we access this entry and it was
            // flagged as available previously, we
            // mark it as used again
            if(cache->ref == 0)
                cache->ref += 1;

            cache->access = time(NULL);

            return &fs->inocache[i];
        }
    }

    zdbfs_lowdebug("[-] cache: miss inode: %u\n", ino);
#endif

    return NULL;
}

inocache_t *zdbfs_cache_add(fuse_req_t req, uint32_t ino, zdb_inode_t *inode) {
#ifndef ZDBFS_CACHE_ENABLED
    (void) req;
    (void) ino;
    (void) inode;
#else
    zdbfs_t *fs = fuse_req_userdata(req);
    inocache_t *cache;

    // if ino already in cache, reuse it and
    // increase reference counter
    if((cache = zdbfs_cache_get(req, ino)))
        return cache;

    // pick up the first empty spot
    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        if(cache->inoid == 0 || cache->ref == 0) {
            // free any previous entry
            zdbfs_inode_free(cache->inode);

            zdbfs_lowdebug("[+] cache: add inode: %u\n", ino);
            cache->inoid = ino;
            cache->ref = 1;
            cache->inode = inode;
            cache->access = time(NULL);

            return &fs->inocache[i];
        }
    }

    // no more space available
    zdbfs_lowdebug("[-] cache: cache full (inode %u)\n", ino);
    // zdbfs_cache_dump(req);

#endif
    return NULL;
}

void zdbfs_cache_release(fuse_req_t req, inocache_t *cache) {
#ifndef ZDBFS_CACHE_ENABLED
    (void) req;
    (void) cache;
#else
    zdbfs_t *fs = fuse_req_userdata(req);

    zdbfs_lowdebug("[+] cache: release inode: %u\n", cache->inoid);

    if(cache->ref > 0)
        cache->ref -= 1;

    if(cache->ref == 0) {
        zdbfs_lowdebug("[+] cache: inode not linked anymore: %u, flushing\n", cache->inoid);

        if(zdbfs_inode_store_backend(fs->mdctx, cache->inode, cache->inoid) != cache->inoid) {
            dies("CACHE", "WRITE FAILED WATRNINFDFJDKLF JDKLF\n");
        }

        // FIXME: cache->inoid = 0;
        // FIXME: maybe invalidate/flush inode
    }
#endif
}

void zdbfs_cache_drop(inocache_t *cache) {
#ifndef ZDBFS_CACHE_ENABLED
    (void) req;
    (void) cache;
#else
    zdbfs_lowdebug("[+] cache: drop inode: %u\n", cache->inoid);

    cache->ref = 0;
    cache->inoid = 0;

    // zdbfs_inode_free(cache->inode);
    cache->inode = NULL;
#endif
}

size_t zdbfs_cache_sync(zdbfs_t *fs) {
    size_t cleared = 0;

    // checking each cache entries and check
    // if entry were added few time ago or more
    //
    // if entry were not touched for some time, flush it
    // in the backend
    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        // check if cache entry is currently in use
        // or waiting to be replaced
        if(cache->ref == 0)
            continue;

        // check if last access time of that entry
        // were recent or not, if it was too recent, let's
        // keep as it in the cache
        if(cache->access > time(NULL) - 10) {
            // printf("[+] cache: hit too early: %ld seconds ago\n", time(NULL) - cache->access);
            continue;
        }

        zdbfs_lowdebug("[+] cache: inode cache expired: %u, flushing\n", cache->inoid);

        if(zdbfs_inode_store_backend(fs->mdctx, cache->inode, cache->inoid) != cache->inoid) {
            dies("cache", "could not write inode in the backend\n");
        }

        // count how many entries were flushed
        cleared += 1;

        // flag entry as re-usable
        cache->ref = 0;
    }

    return cleared;
}

size_t zdbfs_cache_clean(zdbfs_t *fs) {
    size_t flushed = 0;

    // clean and unallocate all entries
    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        if(cache->ref > 0) {
            zdbfs_lowdebug("[+] cache: forcing inode flush: %u\n", cache->inoid);

            // flush still referenced cache entries
            if(zdbfs_inode_store_backend(fs->mdctx, cache->inode, cache->inoid) != cache->inoid) {
                dies("cache", "could not write inode in the backend\n");
            }

            // count how many entries were flushed
            flushed += 1;
        }

        // final unallocation
        zdbfs_inode_free(cache->inode);
    }

    return flushed;
}
