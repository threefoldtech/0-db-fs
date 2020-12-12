#ifndef ZDBFS_CACHE_H
    #define ZDBFS_CACHE_H

    inocache_t *zdbfs_cache_get(fuse_req_t req, uint32_t ino);
    inocache_t *zdbfs_cache_add(fuse_req_t req, uint32_t ino, zdb_inode_t *inode);
    void zdbfs_cache_release(fuse_req_t req, inocache_t *inocache);
    void zdbfs_cache_drop(fuse_req_t req, inocache_t *cache);

    // check for cache content and apply old changes
    size_t zdbfs_cache_sync(zdbfs_t *fs);
    size_t zdbfs_cache_clean(zdbfs_t *fs);

    // dump cache statistics
    void zdbfs_cache_stats(zdbfs_t *fs);
#endif
