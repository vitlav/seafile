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
const char *INIT_INFO = "If you see this page, Seafile HTTP syncing component works.";

const char *GET_HEAD_COMMIT_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/HEAD";

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
default_cb (evhtp_request_t *req, void *arg)
{
    evbuffer_add(req->buffer_out, INIT_INFO, strlen(INIT_INFO));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
get_head_commit_cb (evhtp_request_t *req, void *arg)
{
    SeafileSession *session = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    SeafRepo *repo = seaf_repo_manager_get_repo(session->repo_mgr, repo_id);
    if (!repo) {
        char *error = "Bad repo id\n";
        seaf_warning ("fetch failed: %s\n", error);
        evbuffer_add_printf (req->buffer_out, "%s\n", error);
        evhtp_send_reply(req, EVHTP_RES_BADREQ);

    } else {
        evbuffer_add_printf(req->buffer_out,
                            "repo %.8s head commit is %s\n",
                            repo_id, repo->head->commit_id);
        seaf_repo_unref (repo);
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    g_strfreev (parts);
}

static void
get_request_init (HttpServer *htp_server)
{
    evhtp_set_regex_cb(htp_server->evhtp,
                       GET_HEAD_COMMIT_REGEX, get_head_commit_cb,
                       htp_server->seaf_session);
}

static void *
http_server_run (void *arg)
{
    HttpServer *htp_server = arg;
    htp_server->evbase = event_base_new();
    htp_server->evhtp = evhtp_new(htp_server->evbase, NULL);

    if (evhtp_bind_socket(htp_server->evhtp,
                          htp_server->bind_addr,
                          htp_server->bind_port, 128) < 0) {
        seaf_warning ("Could not bind socket: %s\n", strerror(errno));
        exit(-1);
    }

    evhtp_set_gencb(htp_server->evhtp, default_cb, NULL);

    get_request_init(htp_server);

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
    http_server->seaf_session = session;
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
    if (htp_server->thread_id <= 0)
        return -1;
    return pthread_join (htp_server->thread_id, NULL);
}

int
seaf_http_server_detach (HttpServer *htp_server)
{
    if (htp_server->thread_id <= 0)
        return -1;
    return pthread_detach (htp_server->thread_id);
}

