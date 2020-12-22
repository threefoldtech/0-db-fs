#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <time.h>
#include <sys/time.h>
#include <float.h>
#include "zdbfs.h"
#include "init.h"
#include "inode.h"
#include "cache.h"
#include "zdb.h"

//
// cache statistics
//
int zdbfs_cache_enabled(zdbfs_t *fs) {
    return fs->caching;
}

static void zdbfs_cache_stats_hit(zdbfs_t *fs) {
    fs->stats.cache_hit += 1;
}

static void zdbfs_cache_stats_miss(zdbfs_t *fs) {
    fs->stats.cache_miss += 1;
}

static void zdbfs_cache_stats_full(zdbfs_t *fs) {
    fs->stats.cache_full += 1;
}

//
// block cache system
//

// get current time in microseconds double
double zdbfs_cache_time_now() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (tv.tv_usec / 1000000.0);
}

static blockcache_t *zdbfs_cache_block_first_online(inocache_t *cache) {
    for(size_t i = 0; i < cache->blocks; i++)
        if(cache->blcache[i]->online == 1)
            return cache->blcache[i];

    return NULL;
}

static blockcache_t *zdbfs_cache_block_oldest_online(inocache_t *cache) {
    blockcache_t *online = zdbfs_cache_block_first_online(cache);
    blockcache_t *oldest = online;

    for(size_t i = 0; i < cache->blocks; i++) {
        blockcache_t *block = cache->blcache[i];

        if(block->online == 1 && block->atime < oldest->atime)
            oldest = block;
    }

    return oldest;
}

static blockcache_t *zdbfs_cache_block_delegate(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // looking for oldest (smaller last access time) online block entry
    blockcache_t *oldest = zdbfs_cache_block_oldest_online(cache);

    // move that block in temporary table
    if((oldest->offid = zdb_set(fs->tempctx, oldest->offid, oldest->data, oldest->blocksize)) == 0) {
        dies("cache delegate", "wrong write\n");
    }

    zdbfs_lowdebug("cache: delegate: moved temporarily: %u", oldest->offid);

    //
    // FIXME
    //
    // check for linear access time + full block size and send to real backend for that case
    //

    // free block data and flag entry as offline
    free(oldest->data);
    oldest->data = NULL;
    oldest->online = 0;

    // reduce online cache size
    cache->blonline -= 1;

    return oldest;
}

static int zdbfs_cache_block_restore(zdbfs_t *fs, inocache_t *cache, blockcache_t *block) {
    zdb_reply_t *reply = NULL;

    zdbfs_lowdebug("cache: block offloaded, fetching it back: %u", block->offid);

    if(!(reply = zdb_get(fs->tempctx, block->offid))) {
        zdbfs_debug("[-] cache: temporary: %u: not found\n", block->offid);
        return 1;
    }

    if(!(block->data = malloc(reply->length)))
        diep("cache: block: restore: malloc");

    memcpy(block->data, reply->value, reply->length);
    block->blocksize = reply->length;
    block->online = 1;
    cache->blonline += 1;

    zdbfs_lowdebug("cache: block offloaded restored, %lu bytes read", block->blocksize);
    zdbfs_zdb_reply_free(reply);

    return 0;
}

static void zdbfs_cache_block_free_data(blockcache_t *block) {
    free(block->data);
    block->data = NULL;
}

void zdbfs_cache_block_free(inocache_t *cache) {
    for(size_t i = 0; i < cache->blocks; i++) {
        free(cache->blcache[i]->data);
        free(cache->blcache[i]);
    }

    free(cache->blcache);
    cache->blocks = 0;
    cache->blonline = 0;
    cache->blcache = NULL;
}

blockcache_t *zdbfs_cache_block_get(fuse_req_t req, inocache_t *cache, uint32_t blockidx) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // update cache hit time
    cache->atime = zdbfs_cache_time_now();

    for(size_t i = 0; i < cache->blocks; i++) {
        blockcache_t *block = cache->blcache[i];

        if(block->blockidx == blockidx) {
            block->hits += 1;
            block->atime = zdbfs_cache_time_now();

            // restore offloaded block is not present online
            if(block->online == 0)
                if(zdbfs_cache_block_restore(fs, cache, block))
                    return NULL;

            return block;
        }
    }

    return NULL;
}

void zdbfs_cache_block_hit(blockcache_t *block) {
    block->hits += 1;
    block->atime = zdbfs_cache_time_now();
}

blockcache_t *zdbfs_cache_block_add(fuse_req_t req, inocache_t *cache, uint32_t blockidx) {
    if(cache->blonline + 1 > ZDBFS_BLOCKS_CACHE_LIMIT) {
        zdbfs_lowdebug("cache: too many blocks online [%lu], offloading", cache->blonline);
        zdbfs_cache_block_delegate(req, cache);
    }

    cache->blocks += 1;
    cache->blonline += 1;

    if(!(cache->blcache = realloc(cache->blcache, sizeof(blockcache_t **) * cache->blocks)))
        diep("cache: blocks: realloc");

    if(!(cache->blcache[cache->blocks - 1] = malloc(sizeof(blockcache_t))))
        diep("cache: block: malloc");

    blockcache_t *block = cache->blcache[cache->blocks - 1];

    block->blockidx = blockidx;
    block->data = NULL;
    block->blocksize = 0;
    block->hits = 0;
    block->online = 1;
    block->offid = 0;

    // update cache hit time
    cache->atime = zdbfs_cache_time_now();

    return block;
}

// note: this function doesn't check if block were offloaded of not
//       this check needs to be done before calling it (by get or add)
blockcache_t *zdbfs_cache_block_update(blockcache_t *cache, const char *data, size_t blocksize) {
    if(cache->blocksize != blocksize) {
        free(cache->data);

        if(!(cache->data = malloc(blocksize)))
            diep("cache: block update: mallo");
    }

    memcpy(cache->data, data, blocksize);
    cache->blocksize = blocksize;

    // update hits and access time
    zdbfs_cache_block_hit(cache);

    return cache;
}

//
// cache system
//
inocache_t *zdbfs_cache_get(fuse_req_t req, uint32_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return NULL;

    zdbfs_lowdebug("cache: lookup inode: %u", ino);

    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        if(cache->inoid == ino) {
            zdbfs_lowdebug("cache: hit inode: %u", ino);

            // if we access this entry and it was
            // flagged as available previously, we
            // mark it as used again
            if(cache->ref == 0)
                cache->ref += 1;

            cache->atime = zdbfs_cache_time_now();
            zdbfs_cache_stats_hit(fs);

            return &fs->inocache[i];
        }
    }

    zdbfs_lowdebug("cache: miss inode: %u", ino);
    zdbfs_cache_stats_miss(fs);

    return NULL;
}

inocache_t *zdbfs_cache_add(fuse_req_t req, uint32_t ino, zdb_inode_t *inode) {
    zdbfs_t *fs = fuse_req_userdata(req);
    inocache_t *cache;

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return NULL;

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
            zdbfs_cache_block_free(cache);

            zdbfs_lowdebug("cache: add inode: %u", ino);
            cache->inoid = ino;
            cache->ref = 1;
            cache->inode = inode;
            cache->atime = zdbfs_cache_time_now();
            cache->inode->ino = 1; // FIXME: cache flag

            return &fs->inocache[i];
        }
    }

    // no more space available
    zdbfs_lowdebug("cache: cache full (inode %u)", ino);
    zdbfs_cache_stats_full(fs);
    // zdbfs_cache_dump(req);

    return NULL;
}

static void zdbfs_cache_block_release(zdbfs_t *fs, inocache_t *cache) {
    if(cache->blocks == 0)
        return;

    zdbfs_debug("[+] cache: release: blocks available, flushing\n");

    for(size_t i = 0; i < cache->blocks; i++) {
        blockcache_t *blc = cache->blcache[i];

        if(blc->online == 0)
            if(zdbfs_cache_block_restore(fs, cache, blc))
                return;

        uint32_t blockid = zdbfs_inode_block_get(cache->inode, blc->blockidx);

        zdbfs_lowdebug("cache: release: flushing block %lu [hits %lu]", i, blc->hits);

        if(zdb_set(fs->datactx, blockid, blc->data, blc->blocksize) != blockid) {
            dies("cache flush", "wrong write\n");
        }

        zdbfs_cache_block_free_data(blc);
    }

    // free all blocks
    zdbfs_cache_block_free(cache);
}

void zdbfs_cache_release(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("cache: release inode: %u", cache->inoid);

    if(cache->ref > 0)
        cache->ref -= 1;

    if(cache->ref == 0) {
        zdbfs_lowdebug("cache: inode not linked anymore: %u, flushing", cache->inoid);

        if(zdbfs_inode_store_backend(fs->metactx, cache->inode, cache->inoid) != cache->inoid) {
            dies("cache release", "could not write to backend\n");
        }

        zdbfs_cache_block_release(fs, cache);

        // FIXME: cache->inoid = 0;
        // FIXME: maybe invalidate/flush inode
    }
}

void zdbfs_cache_drop(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("cache: drop inode: %u", cache->inoid);

    cache->ref = 0;
    cache->inoid = 0;

    zdbfs_inode_free(cache->inode);
    zdbfs_cache_block_free(cache);

    cache->inode = NULL;
}

size_t zdbfs_cache_sync(zdbfs_t *fs) {
    size_t cleared = 0;

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return 0;


    // checking each cache entries and check
    // if entry were added few time ago or more
    //
    // if entry were not touched for some time, flush it
    // in the backend
    double now = zdbfs_cache_time_now();
    double expired = now - 10.0;

    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        // check if cache entry is currently in use
        // or waiting to be replaced
        if(cache->ref == 0)
            continue;

        // check if last access time of that entry
        // were recent or not, if it was too recent, let's
        // keep as it in the cache
        if(cache->atime > expired) {
            // printf("[+] cache: hit too early: %f seconds ago\n", now - cache->atime);
            continue;
        }

        zdbfs_lowdebug("cache: inode cache expired: %u, flushing", cache->inoid);

        if(zdbfs_inode_store_backend(fs->metactx, cache->inode, cache->inoid) != cache->inoid) {
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

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return 0;

    // clean and unallocate all entries
    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++) {
        inocache_t *cache = &fs->inocache[i];

        if(cache->ref > 0) {
            zdbfs_lowdebug("cache: forcing inode flush: %u", cache->inoid);

            // flush still referenced cache entries
            if(zdbfs_inode_store_backend(fs->metactx, cache->inode, cache->inoid) != cache->inoid) {
                dies("cache", "could not write inode in the backend\n");
            }

            // count how many entries were flushed
            flushed += 1;
        }

        zdbfs_cache_block_release(fs, cache);

        // final unallocation
        zdbfs_inode_free(cache->inode);
    }

    return flushed;
}

static size_t zdbfs_cache_stats_entries(zdbfs_t *fs) {
    size_t entries = 0;

    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++)
        if(fs->inocache[i].ref > 0)
            entries += 1;

    return entries;
}

static size_t zdbfs_cache_stats_blocksize(zdbfs_t *fs) {
    size_t size = 0;

    for(size_t i = 0; i < ZDBFS_INOCACHE_LENGTH; i++)
        if(fs->inocache[i].blocks > 0)
            for(size_t j = 0; j < fs->inocache[i].blocks; j++)
                size += fs->inocache[i].blcache[j]->blocksize;

    return size;
}

void zdbfs_cache_stats(zdbfs_t *fs) {
    zdbfs_lowdebug("cache: total hit : %lu", fs->stats.cache_hit);
    zdbfs_lowdebug("cache: total miss: %lu", fs->stats.cache_miss);
    zdbfs_lowdebug("cache: total full: %lu", fs->stats.cache_full);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("cache: current entries: %lu", zdbfs_cache_stats_entries(fs));
    zdbfs_lowdebug("cache: current blocksize: %lu bytes", zdbfs_cache_stats_blocksize(fs));
}
