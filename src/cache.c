#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <sys/time.h>
#include <float.h>
#include <errno.h>
#include "zdbfs.h"
#include "init.h"
#include "inode.h"
#include "cache.h"
#include "zdb.h"
#include "system.h"

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

static void zdbfs_cache_stats_linear_flush(zdbfs_t *fs) {
    fs->stats.cache_linear_flush += 1;
}

static void zdbfs_cache_stats_random_flush(zdbfs_t *fs) {
    fs->stats.cache_random_flush += 1;
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

static blockcache_t *zdbfs_cache_block_first_online(inocache_t *cache) {
    for(size_t i = 0; i < cache->blocks; i++)
        if(cache->blcache[i]->online == ZDBFS_BLOCK_ONLINE)
            return cache->blcache[i];

    return NULL;
}

static blockcache_t *zdbfs_cache_block_oldest_online(inocache_t *cache) {
    blockcache_t *online = zdbfs_cache_block_first_online(cache);
    blockcache_t *oldest = online;

    for(size_t i = 0; i < cache->blocks; i++) {
        blockcache_t *block = cache->blcache[i];

        if(block->online == ZDBFS_BLOCK_ONLINE && block->atime < oldest->atime)
            oldest = block;
    }

    return oldest;
}

static int zdbfs_cache_block_linear(inocache_t *cache) {
    double ptime = 0;
    uint32_t next = 0;

    // iterate over all blocks (except last one) ordered
    // and check if block is full and time increased
    //
    // FIXME: does this logic is good enough ?
    for(size_t i = 0; i < cache->blocks - 1; i++) {
        blockcache_t *block = cache->blcache[i];

        // checking for incremented value
        // this disable linear feature for holes
        if(next != block->blockidx)
            return 0;

        next += 1;

        // if any blocks are offloaded, this is not
        // a linear write for sure
        if(block->online == ZDBFS_BLOCK_OFFLINE)
            return 0;

        // skip already flushed blocks
        if(block->online != ZDBFS_BLOCK_FLUSHED)
            continue;

        // block not full
        if(block->blocksize != ZDBFS_BLOCK_SIZE)
            return 0;

        // not time linear
        if(block->atime < ptime)
            return 0;

        ptime = block->atime;
    }

    return 1;
}

// assume that blocks are linear ordered confirmed
static int zdbfs_cache_block_linear_flush(zdbfs_t *fs, inocache_t *cache) {
    int flushed = 0;

    for(size_t i = 0; i < cache->blocks - 1; i++) {
        blockcache_t *block = cache->blcache[i];

        // skip blocks not online
        if(block->online != ZDBFS_BLOCK_ONLINE)
            continue;

        uint32_t blockid = zdbfs_inode_block_get(cache->inode, block->blockidx);
        uint32_t res;

        zdbfs_lowdebug("cache: delegate: flushing: block %u [%lu/%lu]", blockid, i, cache->blocks);

        if((res = zdb_set(fs->datactx, blockid, block->data, block->blocksize) != blockid)) {
            zdbfs_lowdebug("cache: delegate: flushing: response %u, %d", res, zdb_errno);
            warns("cache linear delegate", "wrong write");
            continue;
        }

        zdbfs_lowdebug("cache: delegate: flushed datablock: %u", blockid);

        // free block data and flag entry as flushed
        // (offline but not in temporary namespace)
        zdbfs_cache_block_free_data(block);
        block->online = ZDBFS_BLOCK_FLUSHED;

        flushed += 1;
    }

    return flushed;
}

static int zdbfs_cache_block_delegate(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    //
    // delegate requested, this call is made when cache is full
    // we proceed in two steps:
    //
    // first we check if current state are linears write only
    // in which situation we can directly flush into the backend, we hope that behind
    // it's a regular linear file write and we won't need to update an already written
    // block
    //
    // otherwise, caller is probably doing random write
    // in order to keep backend not growing up too quickly, we will cache blocks which
    // will be updated later, but without sending it to the datablock namespace already,
    // to avoid lot of changes and growup the namespace for no reason
    //
    // we first put that block into the temporary namespace, keep it's id and then flag
    // that block as offline (aka in temporary location), this will free up some blocks
    // in memory

    //
    // check for linear writes
    //
    if(zdbfs_cache_block_linear(cache)) {
        zdbfs_lowdebug("cache: ino: %u, block linear detected, flushing", cache->inoid);

        int flushed = zdbfs_cache_block_linear_flush(fs, cache);
        zdbfs_cache_stats_linear_flush(fs);

        cache->blonline -= flushed;
        zdbfs_lowdebug("cache: flushed: %d", flushed);

        return flushed;
    }

    //
    // free non-recently hit blocks
    //
    zdbfs_lowdebug("cache: ino: %u, non-linear blocks detected, flushing", cache->inoid);
    zdbfs_cache_stats_random_flush(fs);

    // looking for oldest (smaller last access time) online block entry
    blockcache_t *oldest = zdbfs_cache_block_oldest_online(cache);

    // move that block in temporary table
    if((oldest->offid = zdb_set(fs->tempctx, oldest->offid, oldest->data, oldest->blocksize)) == 0) {
        warns("cache delegate", "wrong write");
        return 0;
    }

    zdbfs_lowdebug("cache: delegate: moved temporarily: %u", oldest->offid);

    // free block data and flag entry as offline
    zdbfs_cache_block_free_data(oldest);
    oldest->online = ZDBFS_BLOCK_OFFLINE;

    // reduce online cache size
    cache->blonline -= 1;

    return 1;
}

// take a block from temporary namespace and restore it
// in cache
static int zdbfs_cache_block_restore(zdbfs_t *fs, inocache_t *cache, blockcache_t *block) {
    zdb_reply_t *reply = NULL;

    zdbfs_lowdebug("cache: block offloaded, fetching it back: %u", block->offid);

    if(!(reply = zdb_get(fs->tempctx, block->offid))) {
        zdbfs_debug("[-] cache: temporary: %u: not found\n", block->offid);
        return 1;
    }

    if(!(block->data = malloc(reply->length)))
        zdbfs_sysfatal("cache: block: restore: malloc");

    memcpy(block->data, reply->value, reply->length);
    block->blocksize = reply->length;
    block->online = ZDBFS_BLOCK_ONLINE;
    cache->blonline += 1;

    zdbfs_lowdebug("cache: block offloaded restored, %lu bytes read", block->blocksize);
    zdbfs_zdb_reply_free(reply);

    return 0;
}

// take a block flushed to datablock namespace and restore it
// in cache, this should not happen if linear flush works correctly
// and usage is good
static int zdbfs_cache_block_fetch(zdbfs_t *fs, inocache_t *cache, blockcache_t *block) {
    zdb_reply_t *reply = NULL;
    uint32_t blockid = zdbfs_inode_block_get(cache->inode, block->blockidx);

    zdbfs_lowdebug("cache: block flushed, fetching it back: %u", blockid);

    if(!(reply = zdb_get(fs->datactx, blockid))) {
        zdbfs_debug("[-] cache: datablock: %u: not found\n", blockid);
        return 1;
    }

    if(!(block->data = malloc(reply->length)))
        zdbfs_sysfatal("cache: block: fetch: malloc");

    memcpy(block->data, reply->value, reply->length);
    block->blocksize = reply->length;
    block->online = ZDBFS_BLOCK_ONLINE;
    cache->blonline += 1;

    zdbfs_lowdebug("cache: block flushed restored, %lu bytes read", block->blocksize);
    zdbfs_zdb_reply_free(reply);

    return 0;
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

            // restore offloaded block if not present online
            if(block->online == ZDBFS_BLOCK_OFFLINE)
                if(zdbfs_cache_block_restore(fs, cache, block))
                    return NULL;

            // restore flushed block if not present online
            // this should not happen on real linear write
            if(block->online == ZDBFS_BLOCK_FLUSHED)
                if(zdbfs_cache_block_fetch(fs, cache, block))
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

        if(zdbfs_cache_block_delegate(req, cache) == 0)
            return NULL;
    }

    cache->blocks += 1;
    cache->blonline += 1;

    if(!(cache->blcache = realloc(cache->blcache, sizeof(blockcache_t **) * cache->blocks)))
        zdbfs_sysfatal("cache: blocks: realloc");

    if(!(cache->blcache[cache->blocks - 1] = malloc(sizeof(blockcache_t))))
        zdbfs_sysfatal("cache: block: malloc");

    blockcache_t *block = cache->blcache[cache->blocks - 1];

    block->blockidx = blockidx;
    block->data = NULL;
    block->blocksize = 0;
    block->hits = 0;
    block->online = ZDBFS_BLOCK_ONLINE;
    block->offid = 0;

    // update cache hit time
    cache->atime = zdbfs_cache_time_now();

    return block;
}

// note: this function doesn't check if block were offloaded of not
//       this check needs to be done before calling it (by get or add)
blockcache_t *zdbfs_cache_block_update(blockcache_t *cache, const char *data, size_t blocksize) {
    if(cache->blocksize != blocksize) {
        zdbfs_lowdebug("cache: resize blocksize to: %lu", blocksize);
        free(cache->data);

        if(!(cache->data = malloc(blocksize)))
            zdbfs_sysfatal("cache: block update: malloc");
    }

    memcpy(cache->data, data, blocksize);
    cache->blocksize = blocksize;

    // update hits and access time
    zdbfs_cache_block_hit(cache);

    return cache;
}

//
// inode cache system
//

// get dedicated branch based on inode id
// which is just a selection based on inode id modulo and branch id
static inobranch_t *zdbfs_cache_branch_get(zdbfs_t *fs, uint32_t ino) {
    int inomod = ino % ZDBFS_INOROOT_BRANCHES;
    return &fs->inoroot->branches[inomod];
}

// grow or shrink a branch, clean branch if empty
static inobranch_t *zdbfs_cache_branch_resize(inobranch_t *branch, size_t length) {
    branch->length = length;

    if(!(branch->inocache = realloc(branch->inocache, sizeof(inocache_t *) * branch->length))) {
        // avoid false-error if null returned and length is zero
        if(branch->length > 0)
            zdbfs_sysfatal("cache: branch: resize: realloc");
    }

    return branch;
}

// append an inocache entry to a branch
// (this branch needs to be resize first)
static void zdbfs_cache_branch_push(inobranch_t *branch, inocache_t *cache) {
    branch->inocache[branch->length - 1] = cache;
}

// remove a cache entry from a branch
// the cache entry itself is not freed, only branch is updated
static void zdbfs_cache_branch_pop(inobranch_t *branch, inocache_t *cache) {
    for(size_t i = 0; i < branch->length; i++) {
        if(branch->inocache[i] == cache) {
            zdbfs_lowdebug("cache: pop: swap and clean: %u", cache->inoid);

            // swap last entry with current entry
            branch->inocache[i] = branch->inocache[branch->length - 1];

            // shrink array (will drop last entry, just swapped)
            zdbfs_cache_branch_resize(branch, branch->length - 1);

            return;
        }
    }
}

inocache_t *zdbfs_cache_get(fuse_req_t req, uint32_t ino) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return NULL;

    zdbfs_lowdebug("cache: lookup inode: %u", ino);

    inobranch_t *branch = zdbfs_cache_branch_get(fs, ino);

    for(size_t i = 0; i < branch->length; i++) {
        inocache_t *cache = branch->inocache[i];

        if(cache->inoid == ino) {
            zdbfs_lowdebug("cache: hit inode: %u", ino);

            // if we access this entry and it was
            // flagged as available previously, we
            // mark it as used again
            if(cache->ref == 0)
                cache->ref += 1;

            cache->atime = zdbfs_cache_time_now();
            zdbfs_cache_stats_hit(fs);

            return cache;
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

    inobranch_t *branch = zdbfs_cache_branch_get(fs, ino);
    zdbfs_cache_branch_resize(branch, branch->length + 1);

    if(!(cache = calloc(sizeof(inocache_t), 1)))
        zdbfs_sysfatal("cache: add: calloc");

    // push the new entry to the end of the branch
    zdbfs_cache_branch_push(branch, cache);

    // set entry data
    zdbfs_lowdebug("cache: add inode: %u", ino);
    cache->inoid = ino;
    cache->ref = 1;
    cache->inode = inode;
    cache->atime = zdbfs_cache_time_now();
    cache->inode->ino = 1; // FIXME: cache flag

    return cache;

#if 0
    // FIXME: handle cache full
    // no more space available
    zdbfs_lowdebug("cache: cache full (inode %u)", ino);
    zdbfs_cache_stats_full(fs);
    // zdbfs_cache_dump(req);

    return NULL;
#endif
}

static int zdbfs_cache_block_release(zdbfs_t *fs, inocache_t *cache) {
    if(cache->blocks == 0)
        return 1;

    zdbfs_debug("[+] cache: release: blocks available, flushing\n");

    for(size_t i = 0; i < cache->blocks; i++) {
        blockcache_t *blc = cache->blcache[i];

        if(blc->online == ZDBFS_BLOCK_OFFLINE)
            if(zdbfs_cache_block_restore(fs, cache, blc))
                return 1;

        if(blc->online == ZDBFS_BLOCK_FLUSHED) {
            zdbfs_lowdebug("cache: release: block already flushed: %u", blc->blockidx);
            continue;
        }

        uint32_t blockid = zdbfs_inode_block_get(cache->inode, blc->blockidx);

        zdbfs_lowdebug("cache: release: flushing block %lu [hits %lu]", i, blc->hits);

        if(zdb_set(fs->datactx, blockid, blc->data, blc->blocksize) != blockid) {
            warns("cache flush", "blockid mismatch");
            return 0;
        }

        zdbfs_cache_block_free_data(blc);
    }

    // free all blocks
    zdbfs_cache_block_free(cache);

    return cache->blocks;
}

void zdbfs_cache_drop(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("cache: drop inode: %u", cache->inoid);

    inobranch_t *branch = zdbfs_cache_branch_get(fs, cache->inoid);

    zdbfs_inode_free(cache->inode);
    zdbfs_cache_block_free(cache);

    zdbfs_cache_branch_pop(branch, cache);
    free(cache);
}

int zdbfs_cache_release(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return 1;

    zdbfs_lowdebug("cache: release inode: %u", cache->inoid);

    if(cache->ref > 0)
        cache->ref -= 1;

    if(cache->ref == 0) {
        zdbfs_lowdebug("cache: inode not linked anymore: %u, flushing", cache->inoid);

        if(zdbfs_inode_store_backend(fs->metactx, cache->inode, cache->inoid) != cache->inoid) {
            warns("cache release", "could not write to backend");
            return 0;
        }

        return zdbfs_cache_block_release(fs, cache);
        // zdbfs_cache_drop(req, cache);
        // FIXME ^ better memory usage but slower
    }

    return 1;
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

    for(size_t b = 0; b < fs->inoroot->length; b++) {
        inobranch_t *branch = zdbfs_cache_branch_get(fs, b);

        for(size_t i = 0; i < branch->length; i++) {
            inocache_t *cache = branch->inocache[i];

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
                warns("cache", "could not write inode in the backend");
                continue;
            }

            // count how many entries were flushed
            cleared += 1;

            // flag entry as re-usable
            cache->ref = 0;
        }
    }

    return cleared;
}

size_t zdbfs_cache_clean(zdbfs_t *fs) {
    size_t flushed = 0;

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return 0;

    // clean and unallocate each branches
    for(size_t b = 0; b < fs->inoroot->length; b++) {
        inobranch_t *branch = zdbfs_cache_branch_get(fs, b);

        // uncallocate each entries
        for(size_t i = 0; i < branch->length; i++) {
            inocache_t *cache = branch->inocache[i];

            if(cache->ref > 0) {
                zdbfs_lowdebug("cache: forcing inode flush: %u", cache->inoid);

                // flush still referenced cache entries
                if(zdbfs_inode_store_backend(fs->metactx, cache->inode, cache->inoid) != cache->inoid) {
                    warns("cache", "could not write inode in the backend");
                    continue;
                }

                // count how many entries were flushed
                flushed += 1;
            }

            if(zdbfs_cache_block_release(fs, cache) == 0)
                return flushed;

            // final unallocation
            zdbfs_inode_free(cache->inode);
            free(cache);
        }

        // cleanup branch
        zdbfs_cache_branch_resize(branch, 0);
    }

    return flushed;
}

static size_t zdbfs_cache_stats_entries(zdbfs_t *fs) {
    size_t entries = 0;

    for(size_t b = 0; b < fs->inoroot->length; b++) {
        inobranch_t *branch = zdbfs_cache_branch_get(fs, b);

        for(size_t i = 0; i < branch->length; i++) {
            if(branch->inocache[i]->ref > 0)
                entries += 1;
        }
    }

    return entries;
}

static size_t zdbfs_cache_stats_blocksize(zdbfs_t *fs) {
    size_t size = 0;

    for(size_t b = 0; b < fs->inoroot->length; b++) {
        inobranch_t *branch = zdbfs_cache_branch_get(fs, b);

        for(size_t i = 0; i < branch->length; i++)
            if(branch->inocache[i]->blocks > 0)
                for(size_t j = 0; j < branch->inocache[i]->blocks; j++)
                    size += branch->inocache[i]->blcache[j]->blocksize;
    }

    return size;
}

void zdbfs_cache_stats(zdbfs_t *fs) {
    zdbfs_lowdebug("cache: total hit   : %lu", fs->stats.cache_hit);
    zdbfs_lowdebug("cache: total miss  : %lu", fs->stats.cache_miss);
    zdbfs_lowdebug("cache: total full  : %lu", fs->stats.cache_full);
    zdbfs_lowdebug("cache: linear flush: %lu", fs->stats.cache_linear_flush);
    zdbfs_lowdebug("cache: random flush: %lu", fs->stats.cache_random_flush);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("cache: entries     : %lu", zdbfs_cache_stats_entries(fs));
    zdbfs_lowdebug("cache: blocksize   : %lu bytes", zdbfs_cache_stats_blocksize(fs));
}
