# zdbfs (0-db filesystem)

zdbfs is a fuse filesystem using [0-db](https://github.com/threefoldtech/0-db) as backend.
This filesystem uses some optimization specific needed to keep 0-db backend stable and small, while
providing good performance. 0-db backend provide snapshot, history and runtime backup nearly out-of-box.

# Specifications

zdbfs uses 3 namespaces to keep filesystem state: `metadata`, `datablock`, `temporary`

Metadata (meta) are where inode are written. For now, inode contains metadata about a file or a directory
and their data locations. Directory contains map files/inode aswell. Files contains list of blocks.

Datablock (data) contains the real payload of a file, only files payload are stored there, nothing else.
Each block can be large up-to blocksize, but it's not fixed, non-full blocks are smaller.

Temporary (temp) namespace is a volatile namespace which will get some blocks pushed if the cache
is full, in order to keep memory cache low. Since each insertion create a new entry, namespace
can grow up quickly if too many overwrites occures. This temporary namespace is made to be flushed
when empty, in order to keep is small. This namespace **requires** a password, in order
to use `FLUSH` command, which 0-db enforce to be protected by password.

# Cache

There is a rudimentary cache implementation, used **mainly** for 0-db optimization, not for performance.
Since 0-db is a always append database, sending a datablock while it's updated will result of a lot of
data added in the backend, there is no overwrite. The same applies for inode. If cache is disabled, creating
10 directories in the same directory will store 10 times the directory content in the backend. This can quickly
grow up to unmaintainable namespace.

Cache introduced keep files and directories opened in memory, waiting for operations to be
completed or waiting some time before flushing pending changes to the backend.

# Dependencies

Only `libfuse 3` and `hiredis 1.0` are required to build `zdbfs`, on Linux.
There is for now a hard dependency to `libunwind` for debug purpose. Could become optional later.

Note that, only `gcc` or `clang` are supported as C compiler.

# Build

You can build a debug version with simple `make` command.

To produce a release version (no debug message), you can use `make release` command.

# Options

You can configure zdbfs via runtime arguments to pass via `-o` during mount, eg: `zdbfs -o mh=1.1.1.1,ts=newpwd /mnt/temp`

Available options (with their default value):
```
mh=localhost        metadata zdb hostname
mp=9900             metadata zdb port
mn=zdbfs-meta       metadata namespace name
ms=(not set)        metadata namespace password (optional)

dh=localhost        datablock zdb hostname
dp=9900             datablock zdb port
dn=zdbfs-data       datablock namespace name
ds=(not set)        datablock namespace password (optional)

th=localhost        temporary zdb hostname
tp=9900             temporary zdb port
tn=zdbfs-temp       temporary namespace name
ts=hello            temporary namespace password (mandatory)

nocache             disable runtime cache (for debug purpose)
autons              try to create required namespace on runtime
background          run in background when filesystem is ready
logfile=(not set)   write operations to specified logfile
                    note: this make lot of resolv request and can
                    reduce performance, this could generate large logfile
                    aswell if you do lot of operations
```

# Quick Setup

## Automatic

Start a 0-db locally, in sequential mode:
```
zdb --mode seq
```

Then start `zdbfs` with `autons` option, to mount filesystem on `/mnt/zdbfs`:
```
./zdbfs -o autons /mnt/zdbfs
```

That's it.

## Manual

Start a 0-db locally, in sequential mode:
```
zdb --mode seq
```

Then create required namespaces:
```
cat << EOF | redis-cli -p 9900
NSNEW zdbfs-meta
NSNEW zdbfs-data
NSNEW zdbfs-temp
NSSET zdbfs-temp password hello
NSSET zdbfs-temp public 0
EOF
```

You can now run `./zdbfs /mnt/zdbfs` to mount the filesystem on `/mnt/zdbfs` target.

# Performance

Using 0-db on a basic SSD, 100 MB/s linear write can be achieved easily.

The filesystem can be used as storage to build a Linux kernel with `defconfig` target, with
a fully working result file and compilation process.

More information soon :)

# Specification

Supported operations:
 - `create`
 - `open`
   - Support truncate
 - `lookup`
 - `read`
 - `write`
 - `unlink`
 - `rename`
 - `stat`
 - `statfs`
   - Basic values
 - `opendir`
 - `closedir`
 - `readdir`
 - `link`
 - `symlink`
 - `readlink`
 - `mkdir`
 - `rmdir`
   - Does not delete non-empty directories
 - `ftruncate`
 - `getattr`
 - `setattr`
   - `chmod`
   - `chown`
   - `time`
 - Hole read/write
 - Random read/write

Known unsupported yet:
 - `open`: `O_APPEND` read flag
 - `open`: `O_RD_ONLY`, `O_WRONLY`, `O_RDWR` limitation, everything is allowed
 - User/group permissions internal checking, workaround with fuse default options
 - 
