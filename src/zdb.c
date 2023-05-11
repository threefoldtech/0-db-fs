#define FUSE_USE_VERSION 34

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <inttypes.h>
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include <endian.h>
#include "zdbfs.h"
#include "cache.h"
#include "init.h"
#include "zdb.h"
#include "inode.h"
#include "system.h"

// global zdb errno propagation
int zdb_errno = 0;

// update string and free original one if needed
static char *strup(char *original, char *update) {
    if(original == update)
        return original;

    if(original)
        free(original);

    if(update == NULL)
        return NULL;

    return strdup(update);
}

static redisContext *zdb_new_ctx(char *host, int port, char *unixsock) {
    (void) unixsock;
    redisContext *ctx;

    // unix socket prefered method
    if(unixsock) {
        if(!(ctx = redisConnectUnix(unixsock))) {
            zdbfs_critical("zdb: connect: [%s]: cannot initialize context", unixsock);
            return NULL;
        }

        if(ctx->err) {
            zdbfs_critical("zdb: connect: [%s]: %s", unixsock, ctx->errstr);
            // we keep going, the context is still valid and will trigger
            // an error on usage, but this is not fatal
            return ctx;
        }


    } else {
        if(!(ctx = redisConnect(host, port))) {
            zdbfs_critical("zdb: connect: [%s:%d]: cannot initialize context", host, port);
            return NULL;
        }

        if(ctx->err) {
            zdbfs_critical("zdb: connect: [%s:%d]: %s", host, port, ctx->errstr);
            return ctx;
        }
    }

    return ctx;
}

zdb_t *zdb_new(char *host, int port, char *unixsock) {
    redisContext *ctx;
    zdb_t *zdb;

    if(!(ctx = zdb_new_ctx(host, port, unixsock)))
        return NULL;

    if(!(zdb = calloc(sizeof(zdb_t), 1)))
        zdbfs_sysfatal("zdb: calloc");

    zdb->ctx = ctx;
    zdb->host = strdup(host);
    zdb->port = port;
    zdb->namespace = strdup("(no namespace selected)");

    if(unixsock)
        zdb->socket = strdup(unixsock);

    return zdb;
}

static void zdb_error_recover(zdb_t *remote) {
    zdbfs_debug("[+] zdb: trying to recover zdb connection\n");

    // cleanup existing context, which is not usable anymore
    redisFree(remote->ctx);

    // create new context based on previous settings
    remote->ctx = zdb_new_ctx(remote->host, remote->port, remote->socket);

    // context is created but connection is in error
    // we won't be able to perform a SELECT after that
    //
    // we silently ignore that and next call will trigger
    // an error and a reconnection will be attempted at that moment
    if(remote->ctx->err == REDIS_ERR_IO)
        return;

    // re-select namespace
    zdb_select(remote, remote->namespace, remote->password);
}

int zdb_select(zdb_t *remote, char *namespace, char *password) {
    const char *argv[] = {"SELECT", namespace, password};
    int argc = (password) ? 3 : 2;
    redisReply *reply;

    zdbfs_debug("[+] zdb: select: namespace: %s (pwd: %s)\n", namespace, password ? "yes" : "no");

    if(!(reply = redisCommandArgv(remote->ctx, argc, argv, NULL))) {
        zdbfs_critical("zdb: select: %s: %s", namespace, remote->ctx->errstr);
        zdb_error_recover(remote);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: select: %s: %s", namespace, reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    // update zdb object with current namespace
    remote->namespace = strup(remote->namespace, namespace);
    remote->password = strup(remote->password, password);

    return 0;
}

int zdb_nsnew(zdb_t *remote, char *namespace) {
    const char *argv[] = {"NSNEW", namespace};
    int argc = 2;
    redisReply *reply;

    zdbfs_debug("[+] zdb: nsnew: namespace: %s\n", namespace);

    if(!(reply = redisCommandArgv(remote->ctx, argc, argv, NULL))) {
        zdbfs_critical("zdb: nsnew: %s: %s", namespace, remote->ctx->errstr);
        zdb_error_recover(remote);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: nsnew: %s: %s", namespace, reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

int zdb_flush(zdb_t *remote) {
    const char *argv[] = {"FLUSH"};
    redisReply *reply;

    zdbfs_debug("[+] zdb: flush: namespace: %p\n", remote);

    if(!(reply = redisCommandArgv(remote->ctx, 1, argv, NULL))) {
        zdbfs_critical("zdb: %s: flush: %s", remote->namespace, remote->ctx->errstr);
        zdb_error_recover(remote);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: %s: flush: %s", remote->namespace, reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

int zdb_nsset(zdb_t *remote, char *namespace, char *setting, char *value) {
    const char *argv[] = {"NSSET", namespace, setting, value};
    int argc = 4;
    redisReply *reply;

    zdbfs_debug("[+] zdb: nsset: namespace: %s, %s = %s\n", namespace, setting, value);

    if(!(reply = redisCommandArgv(remote->ctx, argc, argv, NULL))) {
        zdbfs_critical("zdb: %s: nsset: %s: %s", remote->namespace, namespace, remote->ctx->errstr);
        zdb_error_recover(remote);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: %s: nsset: %s", remote->namespace, reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

static size_t zdb_nsinfo_sizeval(char *buffer, char *entry) {
    char *match;

    if(!(match = strstr(buffer, entry)))
        return 0;

    match += strlen(entry) + 2;

    return strtoumax(match, NULL, 10);
}

static int zdb_nsinfo_bool(char *buffer, char *entry) {
    char *match;

    if(!(match = strstr(buffer, entry)))
        return 0;

    match += strlen(entry) + 2;

    return (strncmp(match, "yes", 3) == 0);
}

static size_t zdb_nsinfo_internal_id(char *buffer, char *entry) {
    char *match;
    char numbuf[64];

    if(!(match = strstr(buffer, entry)))
        return 0;

    match += strlen(entry) + 2;

    memset(numbuf, 0x00, sizeof(numbuf));
    sprintf(numbuf, "0x");

    // FIXME: loop ? better way ?
    // convert 0xaabbccdd to 0xddccbbaa
    memcpy(numbuf + 2, match + 8, 2);
    memcpy(numbuf + 4, match + 6, 2);
    memcpy(numbuf + 6, match + 4, 2);
    memcpy(numbuf + 8, match + 2, 2);

    // return strtoul(match, NULL, 0);
    return strtoul(numbuf, NULL, 0);
}


static int zdb_locked(redisReply *reply) {
    if(reply->type != REDIS_REPLY_ERROR)
        return 0;

    if(strncmp(reply->str, "Namespace is temporarily locked", 31) == 0) {
        zdbfs_debug("[-] zdb: namespace locked\n");
        return 1;
    }

    return 0;
}

static void zdb_msleep(int msec) {
    struct timespec ts;

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    nanosleep(&ts, &ts);
}

zdb_nsinfo_t *zdb_nsinfo(zdb_t *remote, char *namespace) {
    const char *argv[] = {"NSINFO", namespace};
    zdb_nsinfo_t *nsinfo;
    redisReply *reply;

    // zdbfs_debug("[+] zdb: nsinfo: request namespace: %s\n", namespace);

    if(!(reply = redisCommandArgv(remote->ctx, 2, argv, NULL))) {
        zdbfs_critical("zdb: nsinfo: %s: %s", namespace, remote->ctx->errstr);
        zdb_error_recover(remote);
        return NULL;
    }

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_debug("[+] zdb: %s: nsinfo failed: %s\n", namespace, reply->str);
        freeReplyObject(reply);
        return NULL;
    }

    if(!(nsinfo = calloc(sizeof(zdb_nsinfo_t), 1)))
        zdbfs_sysfatal("zdb: nsinfo: calloc");

    nsinfo->entries = zdb_nsinfo_sizeval(reply->str, "entries");
    nsinfo->datasize = zdb_nsinfo_sizeval(reply->str, "data_size_bytes");
    nsinfo->nextid = zdb_nsinfo_internal_id(reply->str, "next_internal_id");
    nsinfo->password = zdb_nsinfo_bool(reply->str, "password");

    if(strstr(reply->str, "mode: sequential")) {
        nsinfo->mode = SEQ;

    } else if(strstr(reply->str, "mode: userkey")) {
        nsinfo->mode = USER;
    }

    freeReplyObject(reply);

    return nsinfo;
}

zdb_info_t *zdb_info(zdb_t *remote) {
    const char *argv[] = {"INFO"};
    zdb_info_t *info;
    redisReply *reply;

    zdbfs_debug("[+] zdb: info: request server information\n");

    if(!(reply = redisCommandArgv(remote->ctx, 1, argv, NULL))) {
        zdbfs_critical("zdb: info: %s: %s", remote->namespace, remote->ctx->errstr);
        zdb_error_recover(remote);
        return NULL;
    }

    if(!(info = calloc(sizeof(zdb_nsinfo_t), 1)))
        zdbfs_sysfatal("zdb: info: calloc");

    info->seqsize = zdb_nsinfo_sizeval(reply->str, "sequential_key_size");

    freeReplyObject(reply);

    return info;
}

zdb_reply_t *zdb_get(zdb_t *remote, uint64_t id) {
    uint64_t bid = id; // htobe64(id);
    char *rid = (char *) &bid;
    const char *argv[] = {"GET", rid};
    size_t argvl[] = {3, sizeof(id)};
    zdb_reply_t *reply;

    zdbfs_debug("[+] zdb: %s: get: request id: %lu\n", remote->namespace, id);

    if(!(reply = calloc(sizeof(zdb_reply_t), 1)))
        zdbfs_sysfatal("zdb: get: malloc");

    if(!(reply->rreply = redisCommandArgv(remote->ctx, 2, argv, argvl))) {
        zdbfs_critical("zdb: %s: get: id %lu: %s", remote->namespace, id, remote->ctx->errstr);
        zdb_error_recover(remote);
        free(reply);
        return NULL;
    }

    if(reply->rreply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: %s: get: error: %s", remote->namespace, reply->rreply->str);
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    if(reply->rreply->type == REDIS_REPLY_NIL) {
        zdbfs_debug("[+] zdb: %s: get: nil\n", remote->namespace);
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    zdbfs_debug("[+] zdb: %s: get: response length: %lu bytes\n", remote->namespace, reply->rreply->len);

    reply->value = (uint8_t *) reply->rreply->str;
    reply->length = reply->rreply->len;

    return reply;
}

uint64_t zdb_set(zdb_t *remote, uint64_t id, const void *buffer, size_t length) {
    redisReply *reply = NULL;
    uint64_t response = 0;
    uint64_t bresponse = 0;
    uint64_t bid = id; // htobe64(id);
    char *rid = (char *) &bid;
    size_t rsize = sizeof(id);

    zdbfs_debug("[+] zdb: %s: set: update id: %lu, %lu bytes\n", remote->namespace, id, length);

    // create new entry
    if(id == 0) {
        rsize = 0;
        rid = NULL;
    }

    const char *argv[] = {"SET", rid, buffer};
    size_t argvl[] = {3, rsize, length};

    do {
        if(reply) {
            freeReplyObject(reply);
            zdb_msleep(100);
        }

        if(!(reply = redisCommandArgv(remote->ctx, 3, argv, argvl))) {
            zdbfs_critical("zdb: %s: set: id %lu: %s", remote->namespace, id, remote->ctx->errstr);
            zdb_error_recover(remote);
            return 0;
        }

    } while(zdb_locked(reply));

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: %s: set: error: %s", remote->namespace, reply->str);
        zdb_errno = EIO;

        if(strcmp(reply->str, "Namespace definitely full") == 0)
            zdb_errno = ENOSPC;

        if(strcmp(reply->str, "No space left on this namespace") == 0)
            zdb_errno = ENOSPC;

        freeReplyObject(reply);
        return 0;
    }

    if(reply->type == REDIS_REPLY_NIL) {
        // if response is zero
        // this mean entry was not updated (no changes)
        // but it's a valid a reponse, not an error
        zdbfs_debug("[+] zdb: %s: set: key already up-to-date\n", remote->namespace);
        freeReplyObject(reply);
        return id;
    }

    if(reply->len == sizeof(id)) {
        memcpy(&bresponse, reply->str, sizeof(id));
        response = bresponse; // be64toh(bresponse);
        zdbfs_debug("[+] zdb: %s: set: reponse id: %lu\n", remote->namespace, response);
    }

    freeReplyObject(reply);

    return response;
}

// like zdb_set but only support initial entry (id 0)
uint64_t zdb_set_initial(zdb_t *remote, const void *buffer, size_t length, int update) {
    redisReply *reply;
    uint64_t response = 0;
    char *payload = NULL;
    size_t size = 0;

    // perform an update on id 0, not an insertion
    if(update) {
        // use response as variable to specify id 0
        payload = (char *) &response;
        size = sizeof(response);
    }

    zdbfs_debug("[+] zdb: %s: set initial [id 0]: %lu bytes\n", remote->namespace, length);

    if(!(reply = redisCommand(remote->ctx, "SET %b %b", payload, size, buffer, length))) {
        zdbfs_critical("zdb: initial set: %s", remote->ctx->errstr);
        zdb_error_recover(remote);
        return 1;
    }

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: set initial: redis error reply: %s", "undefined");
        freeReplyObject(reply);
        return 1;
    }

    if(reply->type == REDIS_REPLY_NIL) {
        // if response is zero
        // this mean entry was not updated (no changes)
        // but it's a valid a reponse, not an error
        zdbfs_debug("[+] zdb: %s: set initial: key already up-to-date\n", remote->namespace);
        freeReplyObject(reply);
        return 0;
    }

    if(reply->len != sizeof(response)) {
        zdbfs_critical("zdb: initial set: wrong response size [length: %lu]", reply->len);
        freeReplyObject(reply);
        return 1;
    }

    // all good, let's see what's the response id (which should be zero)
    memcpy(&response, reply->str, sizeof(response));
    zdbfs_debug("[+] zdb: %s: set initial: reponse id: %lu\n", remote->namespace, response);

    freeReplyObject(reply);

    return response;
}

int zdb_del(zdb_t *remote, uint64_t id) {
    uint64_t bid = id; // htobe64(id);
    char *rid = (char *) &bid;
    const char *argv[] = {"DEL", rid};
    size_t argvl[] = {3, sizeof(id)};
    redisReply *reply = NULL;

    zdbfs_debug("[+] zdb: %s: del: request id: %lu\n", remote->namespace, id);

    do {
        if(reply) {
            freeReplyObject(reply);
            zdb_msleep(100);
        }

        if(!(reply = redisCommandArgv(remote->ctx, 2, argv, argvl))) {
            zdbfs_critical("zdb: %s: del: id %lu: %s", remote->namespace, id, remote->ctx->errstr);
            zdb_error_recover(remote);
            return 1;
        }

    } while(zdb_locked(reply));

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: %s: del: error: %s", remote->namespace, reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

int zdbfs_zdb_create(zdbfs_t *fs) {
    zdbfs_verbose("[+] zdb: auto creating namespace\n");
    zdb_nsinfo_t *info;

    // metadata
    // checking if namespace already exists
    if(!(info = zdb_nsinfo(fs->metactx, fs->opts->meta_ns))) {
        if(zdb_nsnew(fs->metactx, fs->opts->meta_ns)) {
            zdbfs_critical("zdb: could not auto create metadata namespace: %s", fs->opts->meta_ns);
            return 1;
        }

        // fetching newly created information
        info = zdb_nsinfo(fs->metactx, fs->opts->meta_ns);
    }

    if(info->mode != SEQ) {
        if(zdb_nsset(fs->metactx, fs->opts->meta_ns, "mode", "seq")) {
            zdbfs_critical("zdb: could not auto set metadata namespace mode: %s", fs->opts->meta_ns);
            return 1;
        }
    }

    // data
    // checking if namespace already exists
    if(!(info = zdb_nsinfo(fs->datactx, fs->opts->data_ns))) {
        if(zdb_nsnew(fs->datactx, fs->opts->data_ns)) {
            zdbfs_critical("zdb: could not auto create data namespace: %s", fs->opts->data_ns);
            return 1;
        }

        info = zdb_nsinfo(fs->datactx, fs->opts->data_ns);
    }

    if(info->mode != SEQ) {
        if(zdb_nsset(fs->datactx, fs->opts->data_ns, "mode", "seq")) {
            zdbfs_critical("zdb: could not auto set data namespace mode: %s", fs->opts->data_ns);
            return 1;
        }
    }

    // temporary
    if(!(info = zdb_nsinfo(fs->tempctx, fs->opts->temp_ns))) {
        if(zdb_nsnew(fs->tempctx, fs->opts->temp_ns)) {
            zdbfs_critical("zdb: could not auto create temporary namespace: %s", fs->opts->temp_ns);
            return 1;
        }

        info = zdb_nsinfo(fs->tempctx, fs->opts->temp_ns);
    }

    if(info->mode != SEQ) {
        if(zdb_nsset(fs->tempctx, fs->opts->temp_ns, "mode", "seq")) {
            zdbfs_critical("zdb: could not auto set temporary namespace mode: %s", fs->opts->temp_ns);
            return 1;
        }
    }

    if(zdb_nsset(fs->tempctx, fs->opts->temp_ns, "public", "0")) {
        zdbfs_critical("zdb: could not auto set temporary namespace public: %s", fs->opts->temp_ns);
        return 1;
    }

    if(zdb_nsset(fs->tempctx, fs->opts->temp_ns, "password", fs->opts->temp_pass)) {
        zdbfs_critical("zdb: could not auto set temporary namespace password: %s",fs->opts->temp_ns);
        return 1;
    }

    return 0;
}

int zdbfs_zdb_connect(zdbfs_t *fs) {
    //
    // metadata
    //
    zdbfs_debug("[+] zdb: connecting metadata zdb\n");

    if(!(fs->metactx = zdb_new(fs->opts->meta_host, fs->opts->meta_port, fs->opts->meta_unix)))
        return 1;

    // could not initialize connection
    if(fs->metactx->ctx->err != 0)
        return 1;

    //
    // data
    //
    zdbfs_debug("[+] zdb: connecting datablock zdb\n");

    if(!(fs->datactx = zdb_new(fs->opts->data_host, fs->opts->data_port, fs->opts->data_unix)))
        return 1;

    // could not initialize connection
    if(fs->datactx->ctx->err != 0)
        return 1;

    //
    // temporary blocks
    //
    zdbfs_debug("[+] zdb: connecting temporary zdb\n");

    if(!(fs->tempctx = zdb_new(fs->opts->temp_host, fs->opts->temp_port, fs->opts->temp_unix)))
        return 1;

    // could not initialize connection
    if(fs->tempctx->ctx->err != 0)
        return 1;

    //
    // auto-create namespace flag
    //
    if(fs->autons) {
        if(zdbfs_zdb_create(fs) != 0)
            return 1;
    }

    //
    // select namespaces
    //
    if(zdb_select(fs->metactx, fs->opts->meta_ns, fs->opts->meta_pass))
        return 1;

    if(zdb_select(fs->datactx, fs->opts->data_ns, fs->opts->data_pass))
        return 1;

    if(zdb_select(fs->tempctx, fs->opts->temp_ns, fs->opts->temp_pass))
        return 1;

    // zdbfs_zdb_benchmark(fs->tempctx);

    return 0;
}

#if 0
void zdbfs_zdb_benchmark(redisContext *remote) {
    char *buffer;
    size_t buflen = ZDBFS_BLOCK_SIZE;
    int pass = 32768;

    if(!(buffer = malloc(buflen)))
        zdbfs_sysfatal("benchmark: malloc");

    memset(buffer, 0x01, buflen);

    double start = zdbfs_cache_time_now();

    for(int i = 0; i < pass; i++) {
        printf("buffer %d\n", i);
        zdb_set(remote, 0, buffer, buflen);
    }

    double end = zdbfs_cache_time_now();

    double sizemb = (pass * buflen) / (1024 * 1024.0);
    printf("%.3f -- %.3f MB -- %.3f MB/s\n", end - start, sizemb, sizemb / (end - start));

    zdb_flush(remote);
    free(buffer);
}
#endif

void zdbfs_zdb_reply_free(zdb_reply_t *reply) {
    if(!reply->rreply)
        free(reply->value);

    if(reply->rreply)
        freeReplyObject(reply->rreply);

    free(reply);
}

void zdb_free(zdb_t *zdb) {
    redisFree(zdb->ctx);
    free(zdb->namespace);
    free(zdb->password);
    free(zdb->host);
    free(zdb->socket);
    free(zdb);
}

void zdbfs_zdb_free(zdbfs_t *fs) {
    zdb_free(fs->metactx);
    zdb_free(fs->datactx);
    zdb_free(fs->tempctx);
}


