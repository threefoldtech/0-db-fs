#ifndef ZDBFS_ZDB_H
    #define ZDBFS_ZDB_H

    int zdbfs_zdb_connect(zdbfs_t *fs);
    zdb_reply_t *zdb_get(redisContext *remote, uint32_t id);
    uint32_t zdb_set(redisContext *remote, uint32_t id, const void *buffer, size_t length);
    void zdb_free(zdb_reply_t *reply);
    int zdbfs_create(zdbfs_t *fs);
#endif
