#ifndef ZDBFS_CACHE_H
    #define ZDBFS_CACHE_H

    int zdbfs_cache_enabled(zdbfs_t *fs);
    double zdbfs_cache_time_now();

    inocache_t *zdbfs_cache_get(fuse_req_t req, uint64_t ino);
    inocache_t *zdbfs_cache_add(fuse_req_t req, uint64_t ino, zdb_inode_t *inode);
    int zdbfs_cache_release(fuse_req_t req, inocache_t *inocache);
    void zdbfs_cache_drop(fuse_req_t req, inocache_t *cache);

    // check for cache content and apply old changes
    size_t zdbfs_cache_sync(zdbfs_t *fs);
    size_t zdbfs_cache_clean(zdbfs_t *fs);

    // dump cache statistics
    void zdbfs_cache_stats(zdbfs_t *fs);

    size_t zdbfs_cache_stats_entries(zdbfs_t *fs);
    size_t zdbfs_cache_stats_blocksize(zdbfs_t *fs);
    size_t zdbfs_cache_stats_blocks(zdbfs_t *fs);
    size_t zdbfs_cache_stats_branches_entries(zdbfs_t *fs);

    // blocks
    blockcache_t *zdbfs_cache_block_get(fuse_req_t req, inocache_t *cache, uint32_t blockidx);
    blockcache_t *zdbfs_cache_block_add(fuse_req_t req, inocache_t *cache, uint32_t blockidx);
    blockcache_t *zdbfs_cache_block_update(blockcache_t *cache, const char *data, size_t blocksize);
    void zdbfs_cache_block_free(inocache_t *cache);
#endif
