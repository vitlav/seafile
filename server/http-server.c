#include <glib.h>
#include <pthread.h>
#include <string.h>

#include "common.h"
#include "log.h"
#include "http-server.h"
#include "seafile-session.h"

#define DEFAULT_BIND_HOST  "0.0.0.0"
#define DEFAULT_BIND_PORT  8083

const char *GROUP_NAME = "httpserver";
const char *HOST = "host";
const char *PORT = "port";
const char *HELLO_WORD = "<h1>HELLO, WORLD!</h1>";

static void
load_http_config (HttpServer *htp_server, SeafileSession *session)
{
    GError *error = NULL;
    char *host = NULL;
    int port = 0;

    host = g_key_file_get_string (session->config, GROUP_NAME, HOST, &error);
    if (!error) {
        htp_server->bind_addr = host;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'host'\n");
            exit (1);
        }

        htp_server->bind_addr = DEFAULT_BIND_HOST;
        g_clear_error (&error);
    }

    port = g_key_file_get_integer (session->config, GROUP_NAME, PORT, &error);
    if (!error) {
        htp_server->bind_port = port;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'port'\n");
            exit (1);
        }

        htp_server->bind_port = DEFAULT_BIND_PORT;
        g_clear_error (&error);
    }

}

static void
default_cb(evhtp_request_t *req, void *arg)
{
    /* Return empty page. */
    evbuffer_add(req->buffer_out, HELLO_WORD, strlen(HELLO_WORD));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void *
http_server_run (void *arg)
{
    HttpServer *htp_server = arg;
    htp_server->evbase = event_base_new();
    htp_server->evhtp = evhtp_new(htp_server->evbase, NULL);

    evhtp_set_gencb(htp_server->evhtp, default_cb, NULL);

    if (evhtp_bind_socket(htp_server->evhtp,
                          htp_server->bind_addr,
                          htp_server->bind_port, 128) < 0) {
        g_warning ("Could not bind socket: %s\n", strerror(errno));
        exit(-1);
    }

    event_base_loop(htp_server->evbase, 0);

    evhtp_unbind_socket(htp_server->evhtp);
    evhtp_free(htp_server->evhtp);
    event_base_free(htp_server->evbase);
    return NULL;
}

HttpServer *
seaf_http_server_new (struct _SeafileSession *session)
{
    HttpServer *http_server = g_new0 (HttpServer, 1);
    http_server->evbase = NULL;
    http_server->evhtp = NULL;
    http_server->thread_id = 0;
    load_http_config(http_server, session);
    session->http_server = http_server;
    return http_server;
}

int
seaf_http_server_start (HttpServer *htp_server)
{
   int ret = pthread_create (&htp_server->thread_id, NULL, http_server_run, htp_server);
   if (ret != 0)
       return -1;
   else
       return 0;
}

int
seaf_http_server_join (HttpServer *htp_server)
{
    if (htp_server->thread_id < 0)
        return -1;
    return pthread_join (htp_server->thread_id, NULL);
}

int
seaf_http_server_detach (HttpServer *htp_server)
{
    if (htp_server->thread_id < 0)
        return -1;
    return pthread_detach (htp_server->thread_id);
}

