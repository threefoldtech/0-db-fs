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

int zdbfs_zdb_connect(zdbfs_t *fs) {
    printf("[+] connecting metadata zdb\n");

    if(!(fs->mdctx = redisConnect("127.0.0.1", 9900)))
        diep("redis init");

    if(fs->mdctx->err) {
        fprintf(stderr, "[-] redis: %s\n", fs->mdctx->errstr);
        return 1;
    }

    printf("[+] connecting data zdb\n");
    if(!(fs->datactx = redisConnect("127.0.0.1", 9900)))
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

    if(!(reply = redisCommand(remote, "SET %b %b", rid, rsize, buffer, length)))
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

// first initialization of the fs
//
// entry 0 will be metadata about information regarding this
// filesystem and additionnal stuff
//
// entry 1 will be the root directory of the system, which will
// be empty in a first set
int zdbfs_create(zdbfs_t *fs) {
    zdb_reply_t *reply;
    char *msg = "zdbfs version 0.1 debug header";
    char *bmsg = "zdbfs block namespace";
    uint32_t expected = 0;

    printf("initial\n");

    // checking if entry 0 exists
    if((reply = zdb_get(fs->mdctx, 0))) {
        if(strncmp((char *) reply->value, "zdbfs ", 6) == 0) {
            printf("[+] init: metadata already contains a valid filesystem\n");
            zdb_free(reply);
            return 0;
        }
    }

    //
    // create initial entry
    //
    redisReply *zreply;

    // cannot use zdb_set because id 0 is special
    if(!(zreply = redisCommand(fs->mdctx, "SET %b %s", NULL, 0, msg)))
        diep("redis: set basic metadata");

    if(memcmp(zreply->str, &expected, zreply->len) != 0)
        dies("could not create initial message", zreply->str);

    freeReplyObject(zreply);


    //
    // create initial root directory (if not there)
    //
    if((reply = zdb_get(fs->mdctx, 1))) {
        printf("[+] init: metadata already contains a valid root directory\n");
        zdb_free(reply);
        return 0;
    }

    zdb_inode_t *inode = zdbfs_mkdir_empty(1, 0755);
    buffer_t root = zdbfs_inode_serialize(inode);

    if(zdb_set(fs->mdctx, 0, root.buffer, root.length) != 1)
        dies("could not create root directory", zreply->str);

    //
    // create initial block
    //
    if((reply = zdb_get(fs->datactx, 0))) {
        printf("[+] init: data already contains a valid signature\n");
        zdb_free(reply);
        return 0;
    }

    // cannot use zdb_set because id 0 is special
    if(!(zreply = redisCommand(fs->datactx, "SET %b %s", NULL, 0, bmsg)))
        diep("redis: set basic data");

    expected = 0;
    if(memcmp(zreply->str, &expected, zreply->len) != 0)
        dies("could not create initial data message", zreply->str);

    freeReplyObject(zreply);

    // FIXME
    // free(root.buffer);

    return 0;
}


