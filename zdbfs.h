#ifndef ZDBFS_H
    #define ZDBFS_H

    #define COLOR_GREY   "\033[30;1m"
    #define COLOR_RED    "\033[31;1m"
    #define COLOR_YELLOW "\033[33;1m"
    #define COLOR_GREEN  "\033[32;1m"
    #define COLOR_CYAN   "\033[36;1m"
    #define COLOR_RESET  "\033[0m"

    #ifndef RELEASE
        #define zdbfs_syscall(fmt, ...) { printf(COLOR_CYAN fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_error(fmt, ...) { printf(COLOR_RED fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_success(fmt, ...) { printf(COLOR_GREEN fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_lowdebug(fmt, ...) { printf(COLOR_GREY fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_verbose(...) { printf(__VA_ARGS__); }
        #define zdbfs_debug(...) { printf(__VA_ARGS__); }
    #else
        #define zdbfs_syscall(...) { printf(__VA_ARGS__); }
        #define zdbfs_error(fmt, ...) { printf(COLOR_RED fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_success(fmt, ...) { printf(COLOR_GREEN fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_verbose(...) { printf(__VA_ARGS__); }
        #define zdbfs_debug(...) ((void)0)
        #define zdbfs_lowdebug(...) ((void)0)
    #endif

    // #define ZDBFS_BLOCK_SIZE          (24 * 1024)
    #define ZDBFS_BLOCK_SIZE          (128 * 1024)
    #define ZDBFS_KERNEL_CACHE_TIME   60.0
    #define ZDBFS_INOCACHE_LENGTH     2048
    #define ZDBFS_EPOLL_MAXEVENTS     64

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
        uint32_t links;
        uint32_t atime;
        uint32_t mtime;
        uint32_t ctime;
        void *extend[];

    } __attribute__((packed)) zdb_inode_t;


    // inode cache entry
    typedef struct inocache_t {
        uint32_t inoid;         // inode number
        size_t ref;             // reference count
        zdb_inode_t *inode;     // pointer to the inode
        time_t access;          // last access time

        uint32_t blockid;
        char *block;

    } inocache_t;

    typedef struct zdbfs_t {
        redisContext *mdctx;
        redisContext *datactx;
        inocache_t *inocache;
        char *tmpblock;

    } zdbfs_t;

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
