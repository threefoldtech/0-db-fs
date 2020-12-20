#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fuse_lowlevel.h>
#include <stddef.h>
#include <hiredis/hiredis.h>
#include "zdbfs.h"
#include "init.h"

//
// argument options
//
#define zdb_opt_field(f) offsetof(zdbfs_options, f)

static struct fuse_opt zdbfs_opts[] = {
    {"mh=%s", zdb_opt_field(meta_host), 0},
    {"mp=%d", zdb_opt_field(meta_port), 0},
    {"mn=%s", zdb_opt_field(meta_ns), 0},
    {"ms=%s", zdb_opt_field(meta_pass), 0},

    {"dh=%s", zdb_opt_field(data_host), 0},
    {"dp=%d", zdb_opt_field(data_port), 0},
    {"dn=%s", zdb_opt_field(data_ns), 0},
    {"ds=%s", zdb_opt_field(data_pass), 0},


    {"th=%s", zdb_opt_field(temp_host), 0},
    {"tp=%d", zdb_opt_field(temp_port), 0},
    {"tn=%s", zdb_opt_field(temp_ns), 0},
    {"ts=%s", zdb_opt_field(temp_pass), 0},

    {"nocache", zdb_opt_field(nocache), 0},
};

int zdbfs_init_args(zdbfs_t *fs, struct fuse_args *args, struct fuse_cmdline_opts *fopts) {
    // setting default values
    memset(fs, 0, sizeof(zdbfs_t));

    if(!(fs->opts = calloc(sizeof(zdbfs_options), 1)))
        diep("init: opts: calloc");

    fs->opts->nocache = -1;

    fs->opts->meta_host = strdup("localhost");
    fs->opts->meta_port = 9900;
    fs->opts->meta_ns = strdup("zdbfs-meta");

    fs->opts->data_host = strdup("localhost");
    fs->opts->data_port = 9900;
    fs->opts->data_ns = strdup("zdbfs-data");

    fs->opts->temp_host = strdup("localhost");
    fs->opts->temp_port = 9900;
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

    return 0;
}

int zdbfs_init_runtime(zdbfs_t *fs) {
    if(fs->opts->temp_pass == NULL && strlen(fs->opts->temp_pass) == 0)
        dies("zdb: temporary namespace", "password cannot be empty");

    // enable cache by default
    fs->caching = (fs->opts->nocache == 0) ? 0 : 1;

    // initialize cache
    if(!(fs->tmpblock = malloc(ZDBFS_BLOCK_SIZE)))
        diep("cache: malloc: block");

    if(!(fs->inocache = (inocache_t *) calloc(sizeof(inocache_t), ZDBFS_INOCACHE_LENGTH)))
        diep("cache: malloc: inocache");

    // check cache status
    if(fs->caching == 0)
        zdbfs_warning("[+] warning: cache disabled [%d]\n", fs->caching);

    return 0;
}

int zdbfs_init_free(zdbfs_t *fs, struct fuse_cmdline_opts *fopts) {
    free(fopts->mountpoint);

    free(fs->tmpblock);
    free(fs->inocache);

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
