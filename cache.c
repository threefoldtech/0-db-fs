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
#include "zdb.h"

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

int zdbfs_cache_enabled(zdbfs_t *fs) {
    return fs->caching;
}

static void zdbfs_cache_stats_hit(zdbfs_t *fs) {
    fs->cachest.hit += 1;
}

static void zdbfs_cache_stats_miss(zdbfs_t *fs) {
    fs->cachest.miss += 1;
}

static void zdbfs_cache_stats_full(zdbfs_t *fs) {
    fs->cachest.full += 1;
}

//
// block cache system
//
void zdbfs_cache_block_free(inocache_t *cache) {
    for(size_t i = 0; i < cache->blocks; i++) {
        free(cache->blcache[i]->data);
        free(cache->blcache[i]);
    }

    free(cache->blcache);
    cache->blocks = 0;
    cache->blcache = NULL;
}

blockcache_t *zdbfs_cache_block_get(inocache_t *cache, uint32_t blockidx) {
    // update cache hit time
    cache->access = time(NULL);

    for(size_t i = 0; i < cache->blocks; i++) {
        if(cache->blcache[i]->blockidx == blockidx) {
            cache->blcache[i]->hits += 1;
            return cache->blcache[i];
        }
    }

    return NULL;
}

blockcache_t *zdbfs_cache_block_add(inocache_t *cache, uint32_t blockidx) {
    cache->blocks += 1;

    if(!(cache->blcache = realloc(cache->blcache, sizeof(blockcache_t **) * cache->blocks)))
        diep("cache: blocks: realloc");

    if(!(cache->blcache[cache->blocks - 1] = malloc(sizeof(blockcache_t))))
        diep("cache: block: malloc");

    blockcache_t *block = cache->blcache[cache->blocks - 1];

    block->blockidx = blockidx;
    block->data = NULL;
    block->blocksize = 0;
    block->hits = 0;

    // update cache hit time
    cache->access = time(NULL);

    return block;
}

blockcache_t *zdbfs_cache_block_update(blockcache_t *cache, const char *data, size_t blocksize) {
    if(cache->blocksize != blocksize) {
        free(cache->data);

        if(!(cache->data = malloc(blocksize)))
            diep("cache: block update: mallo");
    }

    memcpy(cache->data, data, blocksize);
    cache->blocksize = blocksize;
    cache->hits += 1;

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
            zdbfs_cache_stats_hit(fs);

            return &fs->inocache[i];
        }
    }

    zdbfs_lowdebug("[-] cache: miss inode: %u\n", ino);
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

            zdbfs_lowdebug("[+] cache: add inode: %u\n", ino);
            cache->inoid = ino;
            cache->ref = 1;
            cache->inode = inode;
            cache->access = time(NULL);
            cache->inode->ino = 1; // FIXME: cache flag

            return &fs->inocache[i];
        }
    }

    // no more space available
    zdbfs_lowdebug("[-] cache: cache full (inode %u)\n", ino);
    zdbfs_cache_stats_full(fs);
    // zdbfs_cache_dump(req);

    return NULL;
}

void zdbfs_cache_release(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("[+] cache: release inode: %u\n", cache->inoid);

    if(cache->ref > 0)
        cache->ref -= 1;

    if(cache->ref == 0) {
        zdbfs_lowdebug("[+] cache: inode not linked anymore: %u, flushing\n", cache->inoid);

        if(zdbfs_inode_store_backend(fs->mdctx, cache->inode, cache->inoid) != cache->inoid) {
            dies("CACHE", "WRITE FAILED WATRNINFDFJDKLF JDKLF\n");
        }

        if(cache->blocks > 0) {
            zdbfs_debug("[+] cache: blocks available, flushing\n");

            for(size_t i = 0; i < cache->blocks; i++) {
                blockcache_t *blc = cache->blcache[i];
                uint32_t blockid = zdbfs_inode_block_get(cache->inode, blc->blockidx);

                printf("RELEASE BLOCK %lu: hits %lu\n", i, blc->hits);

                if(zdb_set(fs->datactx, blockid, blc->data, blc->blocksize) != blockid) {
                    dies("CACHE FLISH", "wrong write\n");
                }
            }

            zdbfs_cache_block_free(cache);
        }

        // FIXME: cache->inoid = 0;
        // FIXME: maybe invalidate/flush inode
    }

    // zdbfs_cache_block_free(
}

void zdbfs_cache_drop(fuse_req_t req, inocache_t *cache) {
    zdbfs_t *fs = fuse_req_userdata(req);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("[+] cache: drop inode: %u\n", cache->inoid);

    cache->ref = 0;
    cache->inoid = 0;

    zdbfs_inode_free(cache->inode);
    zdbfs_cache_block_free(cache);

    // zdbfs_inode_free(cache->inode);
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

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return 0;

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

        if(cache->blocks > 0) {
            zdbfs_debug("[+] cache: blocks available, flushing\n");

            for(size_t i = 0; i < cache->blocks; i++) {
                blockcache_t *blc = cache->blcache[i];
                uint32_t blockid = zdbfs_inode_block_get(cache->inode, blc->blockidx);

                if(zdb_set(fs->datactx, blockid, blc->data, blc->blocksize) != blockid) {
                    dies("CACHE FLISH", "wrong write\n");
                }
            }

            zdbfs_cache_block_free(cache);
        }

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
    zdbfs_lowdebug("[+] cache: total hit : %lu\n", fs->cachest.hit);
    zdbfs_lowdebug("[+] cache: total miss: %lu\n", fs->cachest.miss);
    zdbfs_lowdebug("[+] cache: total full: %lu\n", fs->cachest.full);

    // runtime cache disabled
    if(!zdbfs_cache_enabled(fs))
        return;

    zdbfs_lowdebug("[+] cache: current entries: %lu\n", zdbfs_cache_stats_entries(fs));
    zdbfs_lowdebug("[+] cache: current blocksize: %lu bytes\n", zdbfs_cache_stats_blocksize(fs));
}
