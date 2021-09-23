#ifndef ZDBFS_H
    #define ZDBFS_H

    #define ZDBFS_VERSION  "0.1.9"

    // internal version used for metadata header
    #define ZDBFS_INTERNAL_VERSION  1

    #define COLOR_GREY   "\033[30;1m"
    #define COLOR_RED    "\033[31;1m"
    #define COLOR_GREEN  "\033[32;1m"
    #define COLOR_YELLOW "\033[33;1m"
    #define COLOR_BLUE   "\033[34;1m"
    #define COLOR_PURPLE "\033[35;1m"
    #define COLOR_CYAN   "\033[36;1m"
    #define COLOR_RESET  "\033[0m"

    // define noop keyword
    #define __disabled   ((void) 0)

    // define colors helpers
    #define grey(x)      COLOR_GREY   x COLOR_RESET "\n"
    #define red(x)       COLOR_RED    x COLOR_RESET "\n"
    #define green(x)     COLOR_GREEN  x COLOR_RESET "\n"
    #define yellow(x)    COLOR_YELLOW x COLOR_RESET "\n"
    #define blue         COLOR_BLUE   x COLOR_RESET "\n"
    #define purple       COLOR_PURPLE x COLOR_RESET "\n"
    #define cyan(x)      COLOR_CYAN   x COLOR_RESET "\n"

    #ifndef RELEASE
        #define zdbfs_syscall(name, fmt, ...)  { printf(COLOR_PURPLE "[x] syscall: " name ": " fmt COLOR_RESET "\n", __VA_ARGS__); }

        #define zdbfs_info(fmt, ...)     { printf(  cyan("[+] " fmt), __VA_ARGS__); }
        #define zdbfs_error(fmt, ...)    { printf(   red("[-] " fmt), __VA_ARGS__); }
        #define zdbfs_success(fmt, ...)  { printf( green("[+] " fmt), __VA_ARGS__); }
        #define zdbfs_warning(fmt, ...)  { printf(yellow("[!] " fmt), __VA_ARGS__); }
        #define zdbfs_lowdebug(fmt, ...) { printf(  grey("[.] " fmt), __VA_ARGS__); }
        #define zdbfs_verbose(...)       { printf(__VA_ARGS__); }
        #define zdbfs_debug(...)         { printf(__VA_ARGS__); }
        #define zdbfs_critical(fmt, ...) { fprintf(stderr, red("[-] " fmt), __VA_ARGS__); }
        #define zdbfs_fatal(fmt, ...)    { fprintf(stderr, red("[-] " fmt), __VA_ARGS__); exit(EXIT_FAILURE); }
        #define zdbfs_sysfatal(fmt)      { fprintf(stderr, red("[-] " fmt ": %s"), strerror(errno)); exit(EXIT_FAILURE); }
    #else
        // #define zdbfs_syscall(...) { printf(__VA_ARGS__); }
        #define zdbfs_syscall(...) ((void) 0)

        #define zdbfs_info(fmt, ...)     { printf(  cyan("[+] " fmt), __VA_ARGS__); }
        #define zdbfs_error(fmt, ...)    { printf(   red("[-] " fmt), __VA_ARGS__); }
        #define zdbfs_success(fmt, ...)  { printf( green("[+] " fmt), __VA_ARGS__); }
        #define zdbfs_warning(fmt, ...)  { printf(yellow("[!] " fmt), __VA_ARGS__); }
        #define zdbfs_lowdebug(...)      __disabled
        #define zdbfs_verbose(...)       { printf(__VA_ARGS__); }
        #define zdbfs_debug(...)         __disabled
        #define zdbfs_critical(fmt, ...) { fprintf(stderr, red("[-] " fmt), __VA_ARGS__); }
        #define zdbfs_fatal(fmt, ...)    { fprintf(stderr, red("[-] " fmt), __VA_ARGS__); exit(EXIT_FAILURE); }
        #define zdbfs_sysfatal(fmt)      { fprintf(stderr, red("[-] " fmt ": %s"), strerror(errno)); exit(EXIT_FAILURE); }
    #endif

    #define ZDBFS_BLOCK_SIZE          (128 * 1024)    // 128k
    #define ZDBFS_BLOCKS_CACHE_LIMIT  32              // 32 * 128k (4 MB)

    #define ZDBFS_KERNEL_CACHE_TIME   5.0
    #define ZDBFS_INOCACHE_LENGTH     4096
    #define ZDBFS_EPOLL_MAXEVENTS     64

    #define ZDBFS_IOCTL_SNAPSHOT      _IOR('E', 0, uint64_t)
    #define ZDBFS_IOCTL_STATISTICS    _IOR('E', 1, stats_t)

    typedef struct zdb_blocks_t {
        uint64_t length;
        uint32_t blocks[];

    } __attribute__((packed)) zdb_blocks_t;

    typedef struct zdb_direntry_t {
        uint16_t size;
        uint64_t ino;
        char name[];

    } __attribute__((packed)) zdb_direntry_t;

    // header used for serialization
    typedef struct zdb_dir_header_t {
        uint64_t ino;
        uint32_t length;
        // copy of zdb_dir_t without the list

    } zdb_dir_header_t;

    typedef struct zdb_dir_t {
        uint64_t ino;              // inode number for that list
        uint32_t length;           // amount of entries
        zdb_direntry_t **entries;  // entries

    } __attribute__((packed)) zdb_dir_t;

    // directories have indirection list which contains
    // list of entries, but split over 128 lists, this
    // avoid having one single large object contains all
    // entries (and quickly reach 8 MB limit and is not
    // efficient at all).
    #define DIRLIST_SIZE 128

    typedef struct zdb_dir_root_serial_t {
        // save each inode id for each list branch
        uint64_t dirlist[DIRLIST_SIZE];

    } zdb_dir_root_serial_t;

    typedef struct zdb_dir_root_t {
        // memory representation of each list
        zdb_dir_t *dirlist[DIRLIST_SIZE];

    } zdb_dir_root_t;

    typedef struct zdb_inode_t {
        uint32_t mode;
        uint64_t ino; // FIXME: not needed
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

    #define ZDBFS_BLOCK_OFFLINE   0
    #define ZDBFS_BLOCK_ONLINE    1
    #define ZDBFS_BLOCK_FLUSHED   2

    // inode cache entry
    typedef struct blockcache_t {
        uint32_t blockidx;  // inode block index (not block id)
        char *data;         // pointer to the buffer
        size_t blocksize;   // size allocated in memory
        size_t hits;        // number of hits (access)
        int online;         // data available in memory
        uint64_t offid;     // offline (temporary) id
        double atime;       // last access time

    } blockcache_t;


    typedef struct inocache_t {
        uint64_t inoid;         // inode number
        size_t ref;             // reference count
        zdb_inode_t *inode;     // pointer to the inode
        double atime;           // last access time

        ssize_t blocks;         // amount of blocks in memory
        size_t blonline;        // amount of blocks available in memory
        blockcache_t **blcache; // cached blocks list

    } inocache_t;

    #define ZDBFS_INOROOT_BRANCHES    1024

    // inocache cache link, one per branch
    // (see below)
    typedef struct inobranch_t {
        inocache_t **inocache;
        size_t length;

    } inobranch_t;

    // root cache link, will contains 'branches' used to
    // indirect cache list (like hash table)
    typedef struct inoroot_t {
        inobranch_t *branches;
        size_t length;

    } inoroot_t;

    typedef struct stats_t {
        size_t version;

        size_t fuse_reqs;

        size_t cache_hit;
        size_t cache_miss;
        size_t cache_full;
        size_t cache_linear_flush;
        size_t cache_random_flush;
        size_t cache_branches;
        size_t cache_branches_allocated;
        size_t cache_entries;
        size_t cache_blocks;
        size_t cache_blocksize;

        size_t syscall_getattr;
        size_t syscall_setattr;
        size_t syscall_create;
        size_t syscall_readdir;
        size_t syscall_open;
        size_t syscall_read;
        size_t syscall_write;
        size_t syscall_mkdir;
        size_t syscall_unlink;
        size_t syscall_rmdir;
        size_t syscall_rename;
        size_t syscall_link;
        size_t syscall_symlink;
        size_t syscall_statsfs;
        size_t syscall_ioctl;

        size_t read_bytes;
        size_t write_bytes;

        size_t errors;

    } stats_t;

    #define ZDBFS_STATS_VERSION 2

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
        int background;       // fork to background
        int autons;           // runtime namespace create
        char *logfile;        // logfile where logging actions
        int cachesize;        // amount of blocks to keep in cache

    } zdbfs_options;

    typedef struct zdb_t {
        redisContext *ctx;
        char *namespace;
        char *password;
        char *socket;
        char *host;
        int port;

    } zdb_t;

    typedef struct zdbfs_t {
        zdb_t *metactx;    // metadata redis context
        zdb_t *datactx;    // block data redis context
        zdb_t *tempctx;    // temporary redis context

        inoroot_t *inoroot;       // root inode cache link

        // write block reusable buffer allocated a single time
        // to hold temporary buffer for read/write changes
        char *tmpblock;

        int background;           // fork to background
        int caching;              // flag to enable runtime cache
        int autons;               // flag to create namespace on init
        char *logfile;            // global logfile where to log actions
        FILE *logfd;              // log file descriptor
        stats_t stats;            // global statistics
        uint64_t fssize;          // filesystem maximum size to report
        size_t cachesize;         // amount of blocks to keep in cache

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

    typedef enum zdbfs_flags_t {
        ZDBFS_FLAGS_IN_USE = 1,

    } zdbfs_flags_t;

    typedef struct zdbfs_header_t {
        char magic[6];        // magic identifier (eg: ZDBFSM for metadata)
        uint16_t version;     // version to control if it's usable
        uint16_t flags;       // flags (see zdbfs_flags_t
        uint64_t size;        // filesystem size in bytes

    } zdbfs_header_t;

    #define KB(x)   (x / (1024.0))
    #define MB(x)   (x / (1024 * 1024.0))
    #define GB(x)   (x / (1024 * 1024 * 1024.0))
    #define TB(x)   (x / (1024 * 1024 * 1024 * 1024.0))
#endif
