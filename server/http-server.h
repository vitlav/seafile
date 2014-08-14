#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#else
#include <event.h>
#endif

#include <evhtp.h>

#include "block.h"

struct _SeafileSession;

typedef struct HttpServer {
    char *bind_addr;
    int bind_port;
    evbase_t *evbase;
    evhtp_t *evhtp;
    pthread_t thread_id;
    struct _SeafileSession *seaf_session;
} HttpServer;

typedef struct SendBlockData {
    struct _SeafileSession *seaf_session;
    evhtp_request_t *req;
    char *block_id;
    BlockHandle *handle;
    uint32_t bsize;
    uint32_t remain;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendBlockData;


HttpServer *
seaf_http_server_new (struct _SeafileSession *session);

int
seaf_http_server_start (HttpServer *htp_server);

int
seaf_http_server_join (HttpServer *htp_server);

int
seaf_http_server_detach (HttpServer *htp_server);


#endif
