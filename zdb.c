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

    freeReplyObject(reply);

    return nsinfo;
}

zdb_reply_t *zdb_get(redisContext *remote, uint32_t id) {
    char *rid = (char *) &id;
    const char *argv[] = {"GET", rid};
    size_t argvl[] = {3, sizeof(id)};
    zdb_reply_t *reply;

    zdbfs_debug("[+] zdb: get: request id: %u\n", id);

    if(!(reply = calloc(sizeof(zdb_reply_t), 1)))
        zdbfs_sysfatal("zdb: get: malloc");

    if(!(reply->rreply = redisCommandArgv(remote, 2, argv, argvl))) {
        zdbfs_critical("zdb: get: id %d: %s", id, remote->errstr);
        free(reply);
        return NULL;
    }

    if(reply->rreply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: get: error: %s", reply->rreply->str);
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    if(reply->rreply->type == REDIS_REPLY_NIL) {
        zdbfs_debug("[+] zdb: get: nil\n");
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    zdbfs_debug("[+] zdb: get: response length: %lu bytes\n", reply->rreply->len);

    reply->value = (uint8_t *) reply->rreply->str;
    reply->length = reply->rreply->len;

    return reply;
}

uint32_t zdb_set(redisContext *remote, uint32_t id, const void *buffer, size_t length) {
    redisReply *reply;
    uint32_t response = 0;
    uint32_t *rid = &id;
    size_t rsize = sizeof(id);

    zdbfs_debug("[+] zdb: set: update id: %u, %lu bytes\n", id, length);

    // create new entry
    if(id == 0) {
        rsize = 0;
        rid = NULL;
    }

    const char *argv[] = {"SET", (char *) rid, buffer};
    size_t argvl[] = {3, rsize, length};

    if(!(reply = redisCommandArgv(remote, 3, argv, argvl))) {
        zdbfs_critical("zdb: set: id %d: %s", id, remote->errstr);
        return 0;
    }

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("zdb: set: error: %s", reply->str);
        freeReplyObject(reply);
        return 0;
    }

    if(reply->type == REDIS_REPLY_NIL) {
        // if response is zero
        // this mean entry was not updated (no changes)
        // but it's a valid a reponse, not an error
        zdbfs_debug("[+] zdb: set: key already up-to-date\n");
        freeReplyObject(reply);
        return id;
    }

    if(reply->len == sizeof(id)) {
        memcpy(&response, reply->str, sizeof(id));
        zdbfs_debug("[+] zdb: set: reponse id: %u\n", response);
    }

    freeReplyObject(reply);

    return response;
}

int zdb_del(redisContext *remote, uint32_t id) {
    char *rid = (char *) &id;
    const char *argv[] = {"DEL", rid};
    size_t argvl[] = {3, sizeof(id)};
    redisReply *reply;

    zdbfs_debug("[+] zdb: del: request id: %u\n", id);

    if(!(reply = redisCommandArgv(remote, 2, argv, argvl))) {
        zdbfs_critical("zdb: del: id %d: %s", id, remote->errstr);
        return 1;
    }

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_error("[-] zdb: del: error: %s\n", reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

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
