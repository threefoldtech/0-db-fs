#ifndef ZDBFS_H
    #define ZDBFS_H

    #define ZDBFS_VERSION  "0.1.0"

    #define COLOR_GREY   "\033[30;1m"
    #define COLOR_RED    "\033[31;1m"
    #define COLOR_GREEN  "\033[32;1m"
    #define COLOR_YELLOW "\033[33;1m"
    #define COLOR_BLUE   "\033[34;1m"
    #define COLOR_PURPLE "\033[35;1m"
    #define COLOR_CYAN   "\033[36;1m"
    #define COLOR_RESET  "\033[0m"

    #ifndef RELEASE
        #define zdbfs_info(fmt, ...) { printf(COLOR_CYAN fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_syscall(fmt, ...) { printf(COLOR_PURPLE fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_error(fmt, ...) { printf(COLOR_RED fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_success(fmt, ...) { printf(COLOR_GREEN fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_warning(fmt, ...) { printf(COLOR_YELLOW fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_lowdebug(fmt, ...) { printf(COLOR_GREY fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_verbose(...) { printf(__VA_ARGS__); }
        #define zdbfs_debug(...) { printf(__VA_ARGS__); }
    #else
        #define zdbfs_info(fmt, ...) { printf(COLOR_CYAN fmt COLOR_RESET, __VA_ARGS__); }
        // #define zdbfs_syscall(...) { printf(__VA_ARGS__); }
        #define zdbfs_syscall(...) ((void)0)
        #define zdbfs_error(fmt, ...) { printf(COLOR_RED fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_success(fmt, ...) { printf(COLOR_GREEN fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_warning(fmt, ...) { printf(COLOR_YELLOW fmt COLOR_RESET, __VA_ARGS__); }
        #define zdbfs_verbose(...) { printf(__VA_ARGS__); }
        #define zdbfs_debug(...) ((void)0)
        #define zdbfs_lowdebug(...) ((void)0)
    #endif

    #define ZDBFS_BLOCK_SIZE          (128 * 1024)    // 128k
    #define ZDBFS_BLOCKS_CACHE_LIMIT  32             // 512 * 128k (64M)

    #define ZDBFS_KERNEL_CACHE_TIME   5.0
    #define ZDBFS_INOCACHE_LENGTH     4095
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
        uint32_t ino; // FIXME: not needed
        uint32_t dev;
        uint16_t uid;
        uint16_t gid;
        uint64_t size;
        uint32_t links;
        uint32_t atime;  // FIXME: won't support
        uint32_t mtime;
        uint32_t ctime;
        void *extend[];

    } __attribute__((packed)) zdb_inode_t;


    // inode cache entry
    typedef struct blockcache_t {
        uint32_t blockidx;  // inode block index (not block id)
        char *data;         // pointer to the buffer
        size_t blocksize;   // size allocated in memory
        size_t hits;        // number of hits (access)
        int online;         // data available in memory
        uint32_t offid;     // offline (temporary) id
        double atime;       // last access time

    } blockcache_t;

    typedef struct inocache_t {
        uint32_t inoid;         // inode number
        size_t ref;             // reference count
        zdb_inode_t *inode;     // pointer to the inode
        double atime;           // last access time

        size_t blocks;          // amount of blocks in memory
        size_t blonline;        // amount of blocks available in memory
        blockcache_t **blcache; // cached blocks list

    } inocache_t;

    typedef struct stats_t {
        size_t fuse_reqs;

        size_t cache_hit;
        size_t cache_miss;
        size_t cache_full;

    } stats_t;

    typedef struct zdbfs_options {
        char *meta_host;      // metadata zdb host
        int meta_port;        // metadata zdb port
        char *meta_ns;        // metadata namespace name
        char *meta_pass;      // metadata namespace password (optional)

        char *data_host;      // data zdb host
        int data_port;        // data zdb port
        char *data_ns;        // data namespace name
        char *data_pass;      // data namespace password (optional)

        char *temp_host;      // temporary zdb host
        int temp_port;        // temporary zdb port
        char *temp_ns;        // temporary zdb namespace name
        char *temp_pass;      // temporary namespace name (mandatory)

        int nocache;          // runtime cache disabled

    } zdbfs_options;

    typedef struct zdbfs_t {
        redisContext *metactx;    // metadata redis context
        redisContext *datactx;    // block data redis context
        redisContext *tempctx;    // temporary redis context

        inocache_t *inocache;     // root inode cache link

        // write block reusable buffer allocated a single time
        // to hold temporary buffer for read/write changes
        char *tmpblock;

        int caching;              // flag to enable runtime cache
        stats_t stats;            // global statistics

        zdbfs_options *opts;

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
