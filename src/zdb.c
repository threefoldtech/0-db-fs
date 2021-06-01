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
#include "zdbfs.h"
#include "init.h"
#include "zdb.h"
#include "inode.h"
#include "system.h"

// global zdb errno propagation
int zdb_errno = 0;

static char *rnid(redisContext *remote) {
    return (char *) remote->privdata;
}

int zdb_select(redisContext *remote, char *namespace, char *password) {
    const char *argv[] = {"SELECT", namespace, password};
    int argc = (password) ? 3 : 2;
    redisReply *reply;

    zdbfs_debug("[+] zdb: select: namespace: %s (pwd: %s)\n", namespace, password ? "yes" : "no");

    if(!(reply = redisCommandArgv(remote, argc, argv, NULL))) {
        zdbfs_critical("zdb: select: %s: %s", namespace, remote->errstr);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: select: %s: %s", namespace, reply->str);
        freeReplyObject(reply);
        return 1;
    }

    // copy current namespace to redis context
    REDIS_OPTIONS_SET_PRIVDATA(remote, namespace, NULL);

    freeReplyObject(reply);

    return 0;
}

int zdb_nsnew(redisContext *remote, char *namespace) {
    const char *argv[] = {"NSNEW", namespace};
    int argc = 2;
    redisReply *reply;

    zdbfs_debug("[+] zdb: nsnew: namespace: %s\n", namespace);

    if(!(reply = redisCommandArgv(remote, argc, argv, NULL))) {
        zdbfs_critical("zdb: nsnew: %s: %s", namespace, remote->errstr);
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

int zdb_flush(redisContext *remote) {
    const char *argv[] = {"FLUSH"};
    redisReply *reply;

    zdbfs_debug("[+] zdb: flush: namespace: %p\n", remote);

    if(!(reply = redisCommandArgv(remote, 1, argv, NULL))) {
        zdbfs_critical("zdb: %s: flush: %s", rnid(remote), remote->errstr);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: %s: flush: %s", rnid(remote), reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

int zdb_nsset(redisContext *remote, char *namespace, char *setting, char *value) {
    const char *argv[] = {"NSSET", namespace, setting, value};
    int argc = 4;
    redisReply *reply;

    zdbfs_debug("[+] zdb: nsset: namespace: %s, %s = %s\n", namespace, setting, value);

    if(!(reply = redisCommandArgv(remote, argc, argv, NULL))) {
        zdbfs_critical("zdb: %s: nsset: %s: %s", rnid(remote), namespace, remote->errstr);
        return 1;
    }

    if(strcmp(reply->str, "OK") != 0) {
        zdbfs_error("zdb: %s: nsset: %s: %s", rnid(remote), namespace, reply->str);
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

zdb_nsinfo_t *zdb_nsinfo(redisContext *remote, char *namespace) {
    const char *argv[] = {"NSINFO", namespace};
    zdb_nsinfo_t *nsinfo;
    redisReply *reply;

    if(!(nsinfo = calloc(sizeof(zdb_nsinfo_t), 1)))
        zdbfs_sysfatal("zdb: nsinfo: calloc");

    zdbfs_debug("[+] zdb: nsinfo: request namespace: %s\n", namespace);

    if(!(reply = redisCommandArgv(remote, 2, argv, NULL))) {
        zdbfs_critical("zdb: nsinfo: %s: %s", namespace, remote->errstr);
        free(nsinfo);
        return NULL;
    }

    nsinfo->entries = zdb_nsinfo_sizeval(reply->str, "entries");
    nsinfo->datasize = zdb_nsinfo_sizeval(reply->str, "data_size_bytes");
    nsinfo->nextid = zdb_nsinfo_internal_id(reply->str, "next_internal_id");

    freeReplyObject(reply);

    return nsinfo;
}

zdb_reply_t *zdb_get(redisContext *remote, uint32_t id) {
    char *rid = (char *) &id;
    const char *argv[] = {"GET", rid};
    size_t argvl[] = {3, sizeof(id)};
    zdb_reply_t *reply;

    zdbfs_debug("[+] zdb: %s: get: request id: %u\n", rnid(remote), id);

    if(!(reply = calloc(sizeof(zdb_reply_t), 1)))
        zdbfs_sysfatal("zdb: get: malloc");

    if(!(reply->rreply = redisCommandArgv(remote, 2, argv, argvl))) {
        zdbfs_critical("zdb: %s: get: id %d: %s", rnid(remote), id, remote->errstr);
        free(reply);
        return NULL;
    }

    if(reply->rreply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: %s: get: error: %s", rnid(remote), reply->rreply->str);
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    if(reply->rreply->type == REDIS_REPLY_NIL) {
        zdbfs_debug("[+] zdb: %s: get: nil\n", rnid(remote));
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    zdbfs_debug("[+] zdb: %s: get: response length: %lu bytes\n", rnid(remote), reply->rreply->len);

    reply->value = (uint8_t *) reply->rreply->str;
    reply->length = reply->rreply->len;

    return reply;
}

uint32_t zdb_set(redisContext *remote, uint32_t id, const void *buffer, size_t length) {
    redisReply *reply = NULL;
    uint32_t response = 0;
    uint32_t *rid = &id;
    size_t rsize = sizeof(id);

    zdbfs_debug("[+] zdb: %s: set: update id: %u, %lu bytes\n", rnid(remote), id, length);

    // create new entry
    if(id == 0) {
        rsize = 0;
        rid = NULL;
    }

    const char *argv[] = {"SET", (char *) rid, buffer};
    size_t argvl[] = {3, rsize, length};

    do {
        if(reply) {
            freeReplyObject(reply);
            zdb_msleep(100);
        }

        if(!(reply = redisCommandArgv(remote, 3, argv, argvl))) {
            zdbfs_critical("zdb: %s: set: id %d: %s", rnid(remote), id, remote->errstr);
            return 0;
        }

    } while(zdb_locked(reply));

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: %s: set: error: %s", rnid(remote), reply->str);
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
        zdbfs_debug("[+] zdb: %s: set: key already up-to-date\n", rnid(remote));
        freeReplyObject(reply);
        return id;
    }

    if(reply->len == sizeof(id)) {
        memcpy(&response, reply->str, sizeof(id));
        zdbfs_debug("[+] zdb: %s: set: reponse id: %u\n", rnid(remote), response);
    }

    freeReplyObject(reply);

    return response;
}

int zdb_del(redisContext *remote, uint32_t id) {
    char *rid = (char *) &id;
    const char *argv[] = {"DEL", rid};
    size_t argvl[] = {3, sizeof(id)};
    redisReply *reply = NULL;

    zdbfs_debug("[+] zdb: %s: del: request id: %u\n", rnid(remote), id);

    do {
        if(reply) {
            freeReplyObject(reply);
            zdb_msleep(100);
        }

        if(!(reply = redisCommandArgv(remote, 2, argv, argvl))) {
            zdbfs_critical("zdb: %s: del: id %d: %s", rnid(remote), id, remote->errstr);
            return 1;
        }

    } while(zdb_locked(reply));

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: %s: del: error: %s", rnid(remote), reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

int zdbfs_zdb_create(zdbfs_t *fs) {
    zdbfs_verbose("[+] zdb: auto creating namespace\n");

    if(zdb_nsnew(fs->metactx, fs->opts->meta_ns)) {
        zdbfs_critical("zdb: could not auto create metadata namespace: %s", fs->opts->meta_ns);
        return 1;
    }

    if(zdb_nsnew(fs->datactx, fs->opts->data_ns)) {
        zdbfs_critical("zdb: could not auto create data namespace: %s", fs->opts->data_ns);
        return 1;
    }

    if(zdb_nsnew(fs->tempctx, fs->opts->temp_ns)) {
        zdbfs_critical("zdb: could not auto create temporary namespace: %s", fs->opts->temp_ns);
        return 1;
    }

    if(zdb_nsset(fs->metactx, fs->opts->temp_ns, "public", "0")) {
        zdbfs_critical("zdb: could not auto set temporary namespace public: %s", fs->opts->temp_ns);
        return 1;
    }

    if(zdb_nsset(fs->metactx, fs->opts->temp_ns, "password", fs->opts->temp_pass)) {
        zdbfs_critical("zdb: could not auto set temporary namespace password: %s",fs->opts->temp_ns );
        return 1;
    }

    return 0;
}

int zdbfs_zdb_connect(zdbfs_t *fs) {
    //
    // metadata
    //
    zdbfs_debug("[+] zdb: connecting metadata zdb [%s, %d]\n", fs->opts->meta_host, fs->opts->meta_port);

    if(!(fs->metactx = redisConnect(fs->opts->meta_host, fs->opts->meta_port)))
        zdbfs_sysfatal("zdb: connect: metadata");

    if(fs->metactx->err) {
        zdbfs_critical("zdb: metadata: [%s:%d]: %s", fs->opts->meta_host, fs->opts->meta_port, fs->metactx->errstr);
        return 1;
    }

    //
    // data
    //
    zdbfs_debug("[+] zdb: connecting datablock zdb [%s, %d]\n", fs->opts->data_host, fs->opts->data_port);
    if(!(fs->datactx = redisConnect(fs->opts->data_host, fs->opts->data_port)))
        zdbfs_sysfatal("zdb: connect: datablock");

    if(fs->datactx->err) {
        zdbfs_critical("zdb: datablock: [%s:%d]: %s", fs->opts->data_host, fs->opts->data_port, fs->datactx->errstr);
        return 1;
    }

    //
    // temporary blocks
    //
    zdbfs_debug("[+] zdb: connecting temporary zdb [%s, %d]\n", fs->opts->temp_host, fs->opts->temp_port);
    if(!(fs->tempctx = redisConnect(fs->opts->temp_host, fs->opts->temp_port)))
        zdbfs_sysfatal("zdb: connect: temporary");

    if(fs->tempctx->err) {
        zdbfs_critical("zdb: temporary: [%s/%d]: %s", fs->opts->temp_host, fs->opts->temp_port, fs->tempctx->errstr);
        return 1;
    }

    //
    // auto-create namespace flag
    //
    if(fs->autons)
        zdbfs_zdb_create(fs);


    //
    // select namespaces
    //
    if(zdb_select(fs->metactx, fs->opts->meta_ns, fs->opts->meta_pass))
        return 1;

    if(zdb_select(fs->datactx, fs->opts->data_ns, fs->opts->data_pass))
        return 1;

    if(zdb_select(fs->tempctx, fs->opts->temp_ns, fs->opts->temp_pass))
        return 1;

    return 0;
}

void zdbfs_zdb_reply_free(zdb_reply_t *reply) {
    if(!reply->rreply)
        free(reply->value);

    if(reply->rreply)
        freeReplyObject(reply->rreply);

    free(reply);
}

void zdbfs_zdb_free(zdbfs_t *fs) {
    redisFree(fs->metactx);
    redisFree(fs->datactx);
    redisFree(fs->tempctx);
}
