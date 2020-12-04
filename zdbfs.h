#ifndef ZDBFS_H
    #define ZDBFS_H

    #define zdbfs_debug printf
    #define BLOCK_SIZE  4096

    typedef struct zdbfs_t {
        redisContext *mdctx;
        redisContext *datactx;

    } zdbfs_t;

    typedef struct zdb_blocks_t {
        uint64_t length;
        uint32_t blocks[];

    } __attribute__((packed)) zdb_blocks_t;

    typedef struct zdb_direntry_t {
        uint16_t size;
        uint32_t ino;
        char name[];

    } __attribute__((packed)) zdb_direntry_t;

    typedef struct zdb_dir_t {
        uint32_t length;
        zdb_direntry_t *entries[];

    } __attribute__((packed)) zdb_dir_t;

    typedef struct zdb_inode_t {
        uint32_t mode;
        uint32_t ino;
        uint32_t dev;
        uint16_t uid;
        uint16_t gid;
        uint64_t size;
        uint32_t atime;
        uint32_t mtime;
        uint32_t ctime;
        void *extend[];

    } __attribute__((packed)) zdb_inode_t;



    typedef struct buffer_t {
        void *buffer;
        size_t length;

    } buffer_t;

    typedef struct zdb_reply_t {
        redisReply *rreply;
        uint8_t *value;
        size_t length;

    } zdb_reply_t;

    void dies(char *help, char *value);
    void diep(char *str);
#endif
