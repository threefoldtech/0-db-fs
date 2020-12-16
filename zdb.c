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
#include "zdb.h"
#include "inode.h"

// static char *host = "10.241.0.232";
static char *host = "127.0.0.1";

static int zdb_select(redisContext *remote, char *namespace, char *password) {
    redisReply *reply;

    zdbfs_debug("[+] zdb: select: request namespace: %s\n", namespace);

    if(password) {
        if(!(reply = redisCommand(remote, "SELECT %s %s", namespace, password)))
            diep(namespace);
    } else {
        if(!(reply = redisCommand(remote, "SELECT %s", namespace)))
            diep(namespace);
    }

    if(strcmp(reply->str, "OK") != 0)
        dies("metadata namespacd", reply->str);

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
    zdb_nsinfo_t *nsinfo;
    redisReply *reply;

    if(!(nsinfo = calloc(sizeof(zdb_nsinfo_t), 1)))
        diep("zdb: nsinfo: calloc");

    zdbfs_debug("[+] zdb: nsinfo: request namespace: %s\n", namespace);

    if(!(reply = redisCommand(remote, "NSINFO %s", namespace)))
        diep(namespace);

    nsinfo->entries = zdb_nsinfo_sizeval(reply->str, "entries");
    nsinfo->datasize = zdb_nsinfo_sizeval(reply->str, "data_size_bytes");

    freeReplyObject(reply);

    return nsinfo;
}

int zdbfs_zdb_connect(zdbfs_t *fs) {
    //
    // metadata
    //
    zdbfs_debug("[+] zdb: connecting metadata zdb\n");

    if(!(fs->metactx = redisConnect(host, 9900)))
        diep("zdb: init");

    if(fs->metactx->err) {
        fprintf(stderr, "[-] zdb: meta: %s\n", fs->metactx->errstr);
        return 1;
    }

    //
    // data
    //
    zdbfs_debug("[+] zdb: connecting data zdb\n");
    if(!(fs->datactx = redisConnect(host, 9900)))
        diep("zdb: init");

    if(fs->datactx->err) {
        fprintf(stderr, "[-] zdb: data: %s\n", fs->datactx->errstr);
        return 1;
    }

    //
    // temporary blocks
    //
    zdbfs_debug("[+] zdb: connecting temp zdb\n");
    if(!(fs->tempctx = redisConnect(host, 9900)))
        diep("zdb: init");

    if(fs->tempctx->err) {
        fprintf(stderr, "[-] zdb: temp: %s\n", fs->tempctx->errstr);
        return 1;
    }

    //
    // select namespaces
    //
    if(zdb_select(fs->metactx, "zdbfs-meta", NULL))
        return 1;

    if(zdb_select(fs->datactx, "zdbfs-data", NULL))
        return 1;

    if(zdb_select(fs->tempctx, "zdbfs-temp", "hello"))
        return 1;

    return 0;
}

zdb_reply_t *zdb_get(redisContext *remote, uint32_t id) {
    zdb_reply_t *reply;

    zdbfs_debug("[+] zdb: get: request id: %u\n", id);

    if(!(reply = calloc(sizeof(zdb_reply_t), 1)))
        diep("zdb: get: malloc");

    if(!(reply->rreply = redisCommand(remote, "GET %b", &id, sizeof(id))))
        diep("zdb: get");

    if(reply->rreply->type == REDIS_REPLY_ERROR) {
        zdbfs_debug("[-] zdb: get: error: %s\n", reply->rreply->str);
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

    if(!(reply = redisCommandArgv(remote, 3, argv, argvl)))
        diep("zdb: set");

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_debug("[-] zdb: set: error: %s\n", reply->str);
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
    redisReply *reply;

    zdbfs_debug("[+] zdb: del: request id: %u\n", id);

    if(!(reply = redisCommand(remote, "DEL %b", &id, sizeof(id))))
        diep("zdb: del");

    if(reply->type == REDIS_REPLY_ERROR) {
        zdbfs_debug("[-] zdb: del: error: %s\n", reply->str);
        freeReplyObject(reply);
        return 1;
    }

    freeReplyObject(reply);

    return 0;
}

void zdb_free(zdb_reply_t *reply) {
    if(!reply->rreply)
        free(reply->value);

    if(reply->rreply)
        freeReplyObject(reply->rreply);

    free(reply);
}

