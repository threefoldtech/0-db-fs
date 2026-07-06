#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fuse_lowlevel.h>
#include <stddef.h>
#include <hiredis/hiredis.h>
#include <errno.h>
#include "zdbfs.h"
#include "init.h"
#include "system.h"

//
// argument options
//
#define zdb_opt_field(f) offsetof(zdbfs_options, f)

static struct fuse_opt zdbfs_opts[] = {
    {"host=%s", zdb_opt_field(global_host), 0},
    {"unix=%s", zdb_opt_field(global_unix), 0},
    {"port=%d", zdb_opt_field(global_port), 0},

    {"mh=%s", zdb_opt_field(meta_host), 0},
    {"mu=%s", zdb_opt_field(meta_unix), 0},
    {"mp=%d", zdb_opt_field(meta_port), 0},
    {"mn=%s", zdb_opt_field(meta_ns), 0},
    {"ms=%s", zdb_opt_field(meta_pass), 0},

    {"dh=%s", zdb_opt_field(data_host), 0},
    {"du=%s", zdb_opt_field(data_unix), 0},
    {"dp=%d", zdb_opt_field(data_port), 0},
    {"dn=%s", zdb_opt_field(data_ns), 0},
    {"ds=%s", zdb_opt_field(data_pass), 0},


    {"th=%s", zdb_opt_field(temp_host), 0},
    {"tu=%s", zdb_opt_field(temp_unix), 0},
    {"tp=%d", zdb_opt_field(temp_port), 0},
    {"tn=%s", zdb_opt_field(temp_ns), 0},
    {"ts=%s", zdb_opt_field(temp_pass), 0},

    {"size=%llu", zdb_opt_field(size), 0},

    {"nocache",      zdb_opt_field(nocache), 0},
    {"autons",       zdb_opt_field(autons), 0},
    {"background",   zdb_opt_field(background), 0},
    {"logfile=%s",   zdb_opt_field(logfile), 0},
    {"cachesize=%d", zdb_opt_field(cachesize), 0},
    FUSE_OPT_END
};

static int zdbfs_setif_int(int source, int global, int fallback) {
    if(source != 0)
        return source;

    if(source == 0 && global != 0)
        return global;

    return fallback;
}

static char *zdbfs_setif_str(char *source, char *global, char *fallback) {
    if(source != NULL)
        return source;

    if(source == NULL && global != NULL)
        return strdup(global);

    if(fallback)
        return strdup(fallback);

    return NULL;
}

int zdbfs_init_args(zdbfs_t *fs, struct fuse_args *args, struct fuse_cmdline_opts *fopts) {
    // setting default values
    memset(fs, 0, sizeof(zdbfs_t));

    if(!(fs->opts = calloc(sizeof(zdbfs_options), 1)))
        zdbfs_sysfatal("init: opts: calloc");

    fs->opts->nocache = -1;
    fs->opts->background = -1;
    fs->opts->autons = -1;
    fs->opts->cachesize = ZDBFS_BLOCKS_CACHE_LIMIT;
    fs->opts->size = 10ull * 1024 * 1024 * 1024;

    fs->opts->meta_ns = strdup("zdbfs-meta");
    fs->opts->data_ns = strdup("zdbfs-data");
    fs->opts->temp_ns = strdup("zdbfs-temp");
    fs->opts->temp_pass = strdup("hello");

    // parsing fuse options
    if(fuse_parse_cmdline(args, fopts) != 0)
        return 1;

    if(fopts->show_help) {
        printf("usage: zdbfs [options] <mountpoint>\n\n");
        fuse_cmdline_help();
        fuse_lowlevel_help();
        return 1;

    } else if(fopts->show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        return 1;
    }

    if(fopts->mountpoint == NULL) {
        printf("usage: zdbfs [options] <mountpoint>\n");
        printf("       zdbfs --help\n");
        return 1;
    }

    // parsing zdbfs options
    if(fuse_opt_parse(args, fs->opts, zdbfs_opts, NULL) == -1)
        return 1;

    fs->opts->meta_host = zdbfs_setif_str(fs->opts->meta_host, fs->opts->global_host, "localhost");
    fs->opts->meta_port = zdbfs_setif_int(fs->opts->meta_port, fs->opts->global_port, 9900);
    fs->opts->meta_unix = zdbfs_setif_str(fs->opts->meta_unix, fs->opts->global_unix, NULL);

    fs->opts->data_host = zdbfs_setif_str(fs->opts->data_host, fs->opts->global_host, "localhost");
    fs->opts->data_port = zdbfs_setif_int(fs->opts->data_port, fs->opts->global_port, 9900);
    fs->opts->data_unix = zdbfs_setif_str(fs->opts->data_unix, fs->opts->global_unix, NULL);

    fs->opts->temp_host = zdbfs_setif_str(fs->opts->temp_host, fs->opts->global_host, "localhost");
    fs->opts->temp_port = zdbfs_setif_int(fs->opts->temp_port, fs->opts->global_port, 9900);
    fs->opts->temp_unix = zdbfs_setif_str(fs->opts->temp_unix, fs->opts->global_unix, NULL);

    return 0;
}

int zdbfs_init_runtime(zdbfs_t *fs) {
    if(fs->opts->temp_pass == NULL && strlen(fs->opts->temp_pass) == 0)
        dies("zdb: temporary namespace", "password cannot be empty");

    // enable cache by default
    fs->caching = (fs->opts->nocache == 0) ? 0 : 1;
    fs->background = (fs->opts->background == 0) ? 1 : 0;
    fs->autons = (fs->opts->autons == 0) ? 1 : 0;
    fs->logfile = fs->opts->logfile;
    fs->cachesize = fs->opts->cachesize;
    fs->fssize = fs->opts->size;

    zdbfs_verbose("[+] blocks cache size: %lu KB\n", (fs->cachesize * ZDBFS_BLOCK_SIZE) / 1024);
    zdbfs_verbose("[+] virtual filesystem size: %.1f GB\n", GB(fs->fssize));

    // initialize cache
    if(!(fs->tmpblock = malloc(ZDBFS_BLOCK_SIZE)))
        zdbfs_sysfatal("cache: malloc: block");

    // initialize cache root branches
    if(!(fs->inoroot = (inoroot_t *) calloc(sizeof(inoroot_t), 1)))
        zdbfs_sysfatal("init: inoroot: calloc");

    // set amount of branches defined
    fs->inoroot->length = ZDBFS_INOROOT_BRANCHES;

    // pre-allocate empty branches
    if(!(fs->inoroot->branches = (inobranch_t *) calloc(sizeof(inobranch_t), fs->inoroot->length)))
        zdbfs_sysfatal("init: inobranches: malloc");

    // check cache status
    if(fs->caching == 0)
        zdbfs_warning("warning: cache disabled [%d]", fs->caching);

    if(fs->logfile) {
        zdbfs_debug("[+] logfile enabled: %s\n", fs->logfile);

        if(!(fs->logfd = fopen(fs->logfile, "a")))
            zdbfs_sysfatal("could not open logfile");
    }

    // set stats schema version
    fs->stats.version = ZDBFS_STATS_VERSION;

    return 0;
}

int zdbfs_init_free(zdbfs_t *fs, struct fuse_cmdline_opts *fopts) {
    free(fopts->mountpoint);

    free(fs->tmpblock);

    for(size_t i = 0; i < fs->inoroot->length; i++)
        free(fs->inoroot->branches[i].inocache);

    free(fs->inoroot->branches);
    free(fs->inoroot);
    free(fs->logfile);

    if(fs->logfd)
        fclose(fs->logfd);

    free(fs->opts->meta_host);
    free(fs->opts->meta_ns);
    free(fs->opts->meta_pass);
    free(fs->opts->data_host);
    free(fs->opts->data_ns);
    free(fs->opts->data_pass);
    free(fs->opts->temp_host);
    free(fs->opts->temp_ns);
    free(fs->opts->temp_pass);
    free(fs->opts);

    return 0;
}
