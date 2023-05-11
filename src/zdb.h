#ifndef ZDBFS_ZDB_H
    #define ZDBFS_ZDB_H

    extern int zdb_errno;

    typedef enum zdb_mode_t {
        USER,
        SEQ

    } zdb_mode_t;

    typedef struct zdb_nsinfo_t {
        size_t entries;
        size_t datasize;
        size_t nextid;
        int password;
        zdb_mode_t mode;

    } zdb_nsinfo_t;

    typedef struct zdb_info_t {
        size_t seqsize;

    } zdb_info_t;

    int zdbfs_zdb_connect(zdbfs_t *fs);

    void zdbfs_zdb_free(zdbfs_t *fs);
    void zdbfs_zdb_reply_free(zdb_reply_t *reply);

    // perform FLUSH command (clean namespace)
    int zdb_flush(zdb_t *remote);

    // perform GET command (fetch entry)
    zdb_reply_t *zdb_get(zdb_t *remote, uint64_t id);

    // perform SET command (set entry)
    uint64_t zdb_set(zdb_t *remote, uint64_t id, const void *buffer, size_t length);
    uint64_t zdb_set_initial(zdb_t *remote, const void *buffer, size_t length, int update);

    // perform DEL command (delete key)
    int zdb_del(zdb_t *remote, uint64_t id);

    // perform NSINFO command (namespace information)
    zdb_nsinfo_t *zdb_nsinfo(zdb_t *remote, char *namespace);

    // perform INFO command (server information)
    zdb_info_t *zdb_info(zdb_t *remote);

    // perform SELECT command (select namespace)
    int zdb_select(zdb_t *remote, char *namespace, char *password);

#endif
