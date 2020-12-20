#ifndef ZDBFS_INIT_H
    #define ZDBFS_INIT_H

    int zdbfs_init_args(zdbfs_t *fs, struct fuse_args *args, struct fuse_cmdline_opts *fopts);
    int zdbfs_init_runtime(zdbfs_t *fs);
    int zdbfs_init_free(zdbfs_t *fs, struct fuse_cmdline_opts *fopts);
#endif
