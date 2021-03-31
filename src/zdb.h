#ifndef ZDBFS_ZDB_H
    #define ZDBFS_ZDB_H

    extern int zdb_errno;

    typedef struct zdb_nsinfo_t {
        size_t entries;
        size_t datasize;

    } zdb_nsinfo_t;

    int zdbfs_zdb_connect(zdbfs_t *fs);
    void zdbfs_zdb_free(zdbfs_t *fs);

    zdb_reply_t *zdb_get(redisContext *remote, uint32_t id);
    uint32_t zdb_set(redisContext *remote, uint32_t id, const void *buffer, size_t length);
    int zdb_del(redisContext *remote, uint32_t id);
    zdb_nsinfo_t *zdb_nsinfo(redisContext *remote, char *namespace);

    void zdbfs_zdb_reply_free(zdb_reply_t *reply);
#endif
