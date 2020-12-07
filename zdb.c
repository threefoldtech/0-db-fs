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
#include <fuse_lowlevel.h>
#include <hiredis/hiredis.h>
#include "zdbfs.h"
#include "zdb.h"
#include "inode.h"

static char *host = "10.241.0.232";

int zdbfs_zdb_connect(zdbfs_t *fs) {
    zdbfs_debug("[+] backend: connecting metadata zdb\n");

    if(!(fs->mdctx = redisConnect(host, 9900)))
        diep("redis init");

    if(fs->mdctx->err) {
        fprintf(stderr, "[-] redis: %s\n", fs->mdctx->errstr);
        return 1;
    }

    zdbfs_debug("[+] backend: connecting data zdb\n");
    if(!(fs->datactx = redisConnect(host, 9900)))
        diep("redis init");

    if(fs->datactx->err) {
        fprintf(stderr, "[-] redis: %s\n", fs->datactx->errstr);
        return 1;
    }

    redisReply *reply;

    if(!(reply = redisCommand(fs->mdctx, "SELECT metadata")))
        diep("redis select metadata");

    if(strcmp(reply->str, "OK") != 0)
        dies("metadata namespacd", reply->str);

    freeReplyObject(reply);

    if(!(reply = redisCommand(fs->datactx, "SELECT fsdata")))
        diep("redis select data");

    if(strcmp(reply->str, "OK") != 0)
        dies("data namespacd", reply->str);

    freeReplyObject(reply);

    return 0;
}

zdb_reply_t *zdb_get(redisContext *remote, uint32_t id) {
    zdb_reply_t *reply;

    zdbfs_debug("[+] get: zdb: request inode: %u\n", id);

    if(!(reply = calloc(sizeof(zdb_reply_t), 1)))
        diep("reply: malloc");

    if(!(reply->rreply = redisCommand(remote, "GET %b", &id, sizeof(id))))
        diep("redis: get");

    if(reply->rreply->type == REDIS_REPLY_NIL) {
        printf("[+] get: redis reply: nil\n");
        freeReplyObject(reply->rreply);
        free(reply);
        return NULL;
    }

    reply->value = (uint8_t *) reply->rreply->str;
    reply->length = reply->rreply->len;

    return reply;
}

uint32_t zdb_set(redisContext *remote, uint32_t id, const void *buffer, size_t length) {
    redisReply *reply;
    uint32_t response = 0;
    uint32_t *rid = &id;
    size_t rsize = sizeof(id);

    zdbfs_debug("[+] set: zdb: request inode: %u\n", id);

    // create new entry
    if(id == 0) {
        rsize = 0;
        rid = NULL;
    }

    /*
    if(!(reply = redisCommand(remote, "SET %b %b", rid, rsize, buffer, length)))
        diep("redis: set");
    */

    const char *argv[] = {"SET", rid, buffer};
    size_t argvl[] = {3, rsize, length};

    if(!(reply = redisCommandArgv(remote, 3, argv, argvl)))
        diep("redis: set");

    if(reply->type == REDIS_REPLY_ERROR) {
        printf("<< %s\n", reply->str);
        freeReplyObject(reply);
        return 0;
    }

    if(reply->type == REDIS_REPLY_NIL) {
        // if response is zero
        // this mean entry was not updated (no changes)
        // but it's a valid a reponse, not an error
        printf("[+] set: zdb: key already up-to-date\n");
        freeReplyObject(reply);
        return id;
    }

    if(reply->len == sizeof(id))
        memcpy(&response, reply->str, sizeof(id));

    freeReplyObject(reply);

    return response;
}

void zdb_free(zdb_reply_t *reply) {
    freeReplyObject(reply->rreply);
    free(reply);
}

