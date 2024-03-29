#ifndef ZDBFS_INODE_H
    #define ZDBFS_INODE_H

    int zdbfs_inode_init(zdbfs_t *fs);

    size_t zdbfs_inode_dirlist_id(const char *name);

    void zdbfs_inode_dump(zdb_inode_t *inode);
    size_t zdbfs_offset_to_block(off_t off);
    size_t zdbfs_inode_dir_size(zdb_dir_t *dir);
    size_t zdbfs_inode_file_size(zdb_inode_t *inode);
    zdb_dir_t *zdbfs_dir_new();
    zdb_inode_t *zdbfs_inode_deserialize_dir(zdb_t *backend, zdb_inode_t *inode, uint8_t *buffer, size_t length);
    zdb_inode_t *zdbfs_inode_deserialize_file(zdb_inode_t *inode, uint8_t *buffer, size_t length);
    zdb_inode_t *zdbfs_inode_deserialize(zdb_t *backend, uint8_t *buffer, size_t length);
    buffer_t zdbfs_inode_serialize_file(zdb_inode_t *inode);
    buffer_t zdbfs_inode_serialize_dir(zdb_t *backend, zdb_inode_t *inode);
    size_t zdbfs_direntry_size(zdb_direntry_t *entry);
    zdb_direntry_t *zdbfs_direntry_new(uint64_t ino, const char *name);
    zdb_dir_t *zdbfs_dir_append(zdb_dir_t *dir, zdb_direntry_t *entry);
    buffer_t zdbfs_inode_serialize(zdb_t *backend, zdb_inode_t *inode);
    void zdbfs_inode_free(zdb_inode_t *inode);

    zdb_dir_t *zdbfs_inode_dir_get(zdb_inode_t *inode, const char *name);
    zdb_dir_root_t *zdbfs_inode_dir_root_get(zdb_inode_t *inode);
    zdb_dir_root_t *zdbfs_inode_dir_root_set(zdb_inode_t *inode, zdb_dir_root_t *root);
    zdb_dir_t *zdbfs_inode_dir_append(zdb_inode_t *inode, uint64_t ino, const char *name);

    void zdbfs_inode_block_set(zdb_inode_t *inode, size_t block, uint32_t blockid);
    uint32_t zdbfs_inode_block_get(zdb_inode_t *inode, size_t block);
    zdb_reply_t *zdbfs_inode_block_fetch(fuse_req_t req, zdb_inode_t *file, uint64_t ino, uint32_t block);
    uint32_t zdbfs_inode_block_store(fuse_req_t req, zdb_inode_t *inode, uint64_t ino, uint32_t blockid, const char *buffer, size_t buflen);

    zdb_blocks_t *zdbfs_inode_blocks_get(zdb_inode_t *inode);
    int zdbfs_inode_blocks_remove(fuse_req_t req, zdb_inode_t *inode);

    int zdbfs_inode_remove_entry(zdb_inode_t *inode, const char *name);
    int zdbfs_inode_unlink(fuse_req_t req, zdb_inode_t *file, uint64_t ino);

    zdb_direntry_t *zdbfs_inode_lookup_direntry(zdb_inode_t *inode, const char *name);

    void zdbfs_inode_to_stat(struct stat *st, zdb_inode_t *inode, uint64_t ino);
    void zdbfs_inode_to_fuse_param(struct fuse_entry_param *param, zdb_inode_t *inode, uint64_t ino);

    zdb_inode_t *zdbfs_inode_new_file(fuse_req_t req, uint32_t mode);
    zdb_inode_t *zdbfs_inode_new_symlink(fuse_req_t req, const char *link);
    zdb_inode_t *zdbfs_inode_new_dir(uint64_t parent, uint32_t mode);

    const char *zdbfs_inode_symlink_get(zdb_inode_t *inode);

    zdb_inode_t *zdbfs_inode_fetch(fuse_req_t req, fuse_ino_t ino);
    zdb_inode_t *zdbfs_directory_fetch(fuse_req_t req, fuse_ino_t ino);

    uint64_t zdbfs_inode_store_backend(zdb_t *backend, zdb_inode_t *inode, uint64_t ino);
    uint64_t zdbfs_inode_store_metadata(fuse_req_t req, zdb_inode_t *inode, uint64_t ino);
    uint64_t zdbfs_inode_store_data(fuse_req_t req, zdb_inode_t *inode, uint64_t ino);

    int zdbfs_inode_init_release(zdbfs_t *fs);

    char *zdbfs_inode_resolv(fuse_req_t req, fuse_ino_t target, const char *name);
#endif
