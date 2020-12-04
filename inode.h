#ifndef ZDBFS_INODE_H
    #define ZDBFS_INODE_H

    void zdbfs_inode_dump(zdb_inode_t *inode);
    size_t zdbfs_offset_to_block(off_t off);
    void zdbfs_inode_set_block(zdb_inode_t *inode, size_t block, uint32_t blockid);
    size_t zdbfs_inode_dir_size(zdb_dir_t *dir);
    size_t zdbfs_inode_file_size(zdb_inode_t *inode);
    zdb_dir_t *zdbfs_dir_new(uint32_t parent);
    zdb_inode_t *zdbfs_mkdir_empty(uint32_t parent, uint32_t mode);
    zdb_inode_t *zdbfs_inode_deserialize_dir(zdb_inode_t *inode, uint8_t *buffer, size_t length);
    zdb_inode_t *zdbfs_inode_deserialize_file(zdb_inode_t *inode, uint8_t *buffer, size_t length);
    zdb_inode_t *zdbfs_inode_deserialize(uint8_t *buffer, size_t length);
    buffer_t zdbfs_inode_serialize_file(zdb_inode_t *inode);
    buffer_t zdbfs_inode_serialize_dir(zdb_inode_t *inode);
    size_t zdbfs_direntry_size(zdb_direntry_t *entry);
    zdb_direntry_t *zdbfs_direntry_new(uint32_t ino, const char *name);
    zdb_dir_t *zdbfs_dir_append(zdb_dir_t *dir, zdb_direntry_t *entry);
    buffer_t zdbfs_inode_serialize(zdb_inode_t *inode);
    void zdbfs_inode_to_stat(struct stat *st, zdb_inode_t *inode);
    int zdbfs_inode_stat(fuse_req_t req, fuse_ino_t ino, struct stat *stbuf);
    zdb_inode_t *zdbfs_fetch_inode(fuse_req_t req, fuse_ino_t ino);
    zdb_inode_t *zdbfs_fetch_directory(fuse_req_t req, fuse_ino_t ino);
    zdb_inode_t *zdbfs_inode_new_file(fuse_req_t req, uint32_t mode);
#endif
