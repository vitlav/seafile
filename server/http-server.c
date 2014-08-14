#include <pthread.h>
#include <string.h>
#include <jansson.h>

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

const char *GET_COMMIT_INFO_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";

const char *GET_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/fs/.*";

const char *GET_BLOCKT_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/block/[\\da-z]{40}";

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
    evbuffer_add (req->buffer_out, INIT_INFO, strlen(INIT_INFO));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
get_head_commit_cb (evhtp_request_t *req, void *arg)
{
    SeafileSession *session = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    SeafRepo *repo = seaf_repo_manager_get_repo (session->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Get head commit failed: Repo %s is missing or corrupted.\n", repo_id);
        evbuffer_add_printf (req->buffer_out,
                             "Get head commit failed: Repo %s is missing or corrupted.\n",
                             repo_id);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
    } else {
        evbuffer_add (req->buffer_out,
                      repo->head->commit_id, strlen (repo->head->commit_id));
        seaf_repo_unref (repo);
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    g_strfreev (parts);
}

static void
get_commit_info_cb (evhtp_request_t *req, void *arg)
{
    SeafileSession *session = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *commit_id = parts[3];
    char *data = NULL;
    int len;
    int ret = seaf_obj_store_read_obj (session->commit_mgr->obj_store, repo_id, 1,
                                       commit_id, (void **)&data, &len);
#if defined MIGRATION || defined SEAFILE_CLIENT
    /* For compatibility with version 0. */
    if (ret < 0)
        ret = seaf_obj_store_read_obj (session->commit_mgr->obj_store, repo_id, 0,
                                       commit_id, (void **)&data, &len);
#endif

    if (ret < 0) {
        seaf_warning ("Get commit info failed: commit %s is missing.\n", commit_id);
        evbuffer_add_printf (req->buffer_out,
                             "Get commit info failed: commit %s is missing.\n", commit_id);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
    } else {
       evbuffer_add (req->buffer_out, data, len);
       g_free (data);
       evhtp_send_reply (req, EVHTP_RES_OK);
    }
    g_strfreev (parts);
}

static gboolean
get_fs_obj_id (SeafCommit *commit, void *data, gboolean *stop)
{
    if (strlen (commit->root_id) != 40) {
        *stop = TRUE;
        return FALSE;
    }
    GList **list = (GList **)data;
    *list = g_list_prepend (*list, g_strdup(commit->root_id));
    return TRUE;
}

static void
get_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    const char *commit_id = evhtp_kv_find (req->uri->query, "client-head");
    if (commit_id == NULL || strlen (commit_id) != 40) {
        char *error = "Invalid client-head parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }
    SeafileSession *session = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    GList *list = NULL;

    int ret = seaf_commit_manager_traverse_commit_tree (session->commit_mgr, repo_id, 1,
                                                        commit_id, get_fs_obj_id,
                                                        &list, FALSE);
#if defined MIGRATION || defined SEAFILE_CLIENT
    /* For compatibility with version 0. */
    int ret = seaf_commit_manager_traverse_commit_tree (session->commit_mgr, repo_id, 0,
                                                        commit_id, get_fs_obj_id,
                                                        &list, FALSE);
#endif

    if (ret < 0) {
        seaf_warning ("Get FS obj_id failed: commit %s is missing.\n", commit_id);
        evbuffer_add_printf (req->buffer_out,
                             "Get FS obj_id failed: commit %s is missing.\n", commit_id);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
    } else {
        GList *ptr = list;
        json_t *obj_array = json_array ();
        for (; ptr; ptr = ptr->next) {
            json_array_append_new (obj_array, json_string (ptr->data));
            g_free (ptr->data);
        }
        char *obj_list = json_dumps (obj_array, JSON_COMPACT);
        evbuffer_add (req->buffer_out, obj_list, strlen (obj_list));
        evhtp_send_reply (req, EVHTP_RES_OK);
        g_free (obj_list);
        json_decref (obj_array);
        g_list_free (list);
    }
    g_strfreev (parts);
}

static gboolean
test_firefox (evhtp_request_t *req)
{
    const char *user_agent = evhtp_header_find (req->headers_in, "User-Agent");
    if (!user_agent)
        return FALSE;

    GString *s = g_string_new (user_agent);
    if (g_strrstr (g_string_ascii_down (s)->str, "firefox")) {
        g_string_free (s, TRUE);
        return TRUE;
    }
    else {
        g_string_free (s, TRUE);
        return FALSE;
    }
}

static void
free_sendblock_data (SendBlockData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block (data->seaf_session->block_mgr, data->handle);
        seaf_block_manager_block_handle_free (data->seaf_session->block_mgr, data->handle);
    }

    g_free (data->block_id);
    g_free (data);
}

static void
my_block_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendBlockData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendblock_data (data);
}

static void
write_block_data_cb (struct bufferevent *bev, void *ctx)
{
    SendBlockData *data = ctx;
    char *blk_id;
    BlockHandle *handle;
    char buf[1024 * 64];
    int n;

    blk_id = data->block_id;

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block (data->seaf_session->block_mgr,
                                                      data->store_id,
                                                      data->repo_version,
                                                      blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s\n", blk_id);
            goto err;
        }

        data->remain = data->bsize;
    }
    handle = data->handle;

    n = seaf_block_manager_read_block (data->seaf_session->block_mgr,
                                       handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s.\n", blk_id);
        goto err;
    } else if (n == 0) {
        /* We've read up the data of this block, finish. */
        seaf_block_manager_close_block (data->seaf_session->block_mgr, handle);
        seaf_block_manager_block_handle_free (data->seaf_session->block_mgr, handle);
        data->handle = NULL;

        /* Recover evhtp's callbacks */
        bev->readcb = data->saved_read_cb;
        bev->writecb = data->saved_write_cb;
        bev->errorcb = data->saved_event_cb;
        bev->cbarg = data->saved_cb_arg;

        /* Resume reading incomming requests. */
        evhtp_request_resume (data->req);

        evhtp_send_reply_end (data->req);

        free_sendblock_data (data);
        return;
    }

    /* OK, we've got some data to send. */
    bufferevent_write (bev, buf, n);

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_sendblock_data (data);
    return;
}

static void
do_block (evhtp_request_t *req, SeafileSession *session,
         const char *repo_id, const char *block_id)
{
    uint32_t bsize;
    gboolean found = FALSE;
    char blk_size[255];
    char cont_filename[SEAF_PATH_MAX];
    SendBlockData *data;
    int repo_version = 1;

    BlockMetadata *bm = seaf_block_manager_stat_block (session->block_mgr,
                                                       repo_id, 1, block_id);
#if defined MIGRATION || defined SEAFILE_CLIENT
    /* For compatibility with version 0. */
    if (bm == NULL) {
        bm = seaf_block_manager_stat_block (session->block_mgr,
                                            repo_id, 0, block_id);
        repo_version = 0;
    }
#endif
    if (bm && bm->size >= 0) {
        bsize = bm->size;
        found = TRUE;
    }
    g_free (bm);

    /* block not found. */
    if (!found) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new ("Access-Control-Allow-Origin",
                                                "*", 1, 1));

    if (test_firefox (req)) {
        snprintf (cont_filename, SEAF_PATH_MAX,
                  "attachment;filename*=\"utf8\' \'%s\"", block_id);
    } else {
        snprintf (cont_filename, SEAF_PATH_MAX,
                  "attachment;filename=\"%s\"", block_id);
    }
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Disposition", cont_filename,
                                               1, 1));

    snprintf (blk_size, sizeof(blk_size), "%"G_GUINT32_FORMAT"", bsize);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new ("Content-Length", blk_size, 1, 1));

    data = g_new0 (SendBlockData, 1);
    data->req = req;
    data->block_id = g_strdup (block_id);

    memcpy (data->store_id, repo_id, 36);
    data->repo_version = repo_version;
    data->seaf_session = session;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    data->bsize = bsize;
    bufferevent_setcb (bev,
                       NULL,
                       write_block_data_cb,
                       my_block_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Avoid recursive call of write_data_cb(). */
    if (req->htp->ssl_cfg != NULL)
        evbuffer_defer_callbacks (bev->output, bev->ev_base);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start (req, EVHTP_RES_OK);
}

static void
get_block_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *block_id = NULL;
    SeafileSession *session = arg;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    if (evhtp_kv_find (req->headers_in, "If-Modified-Since") != NULL) {
        evhtp_send_reply (req, EVHTP_RES_NOTMOD);
    } else {
        char http_date[256];
        evhtp_kv_t *kv;
        time_t now = time(NULL);

        /* Set Last-Modified header if the client gets this file
         * for the first time. So that the client will set
         * If-Modified-Since header the next time it gets the same
         * file.
         */
#ifndef WIN32
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %T GMT",
                  gmtime(&now));
#else
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %H:%M:%S GMT",
                  gmtime(&now));
#endif
        kv = evhtp_kv_new ("Last-Modified", http_date, 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);

        kv = evhtp_kv_new ("Cache-Control", "max-age=3600", 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);

        do_block (req, session, repo_id, block_id);
    }
    g_strfreev (parts);
}

static void
get_request_init (HttpServer *htp_server)
{
    evhtp_set_regex_cb (htp_server->evhtp,
                        GET_HEAD_COMMIT_REGEX, get_head_commit_cb,
                        htp_server->seaf_session);

    evhtp_set_regex_cb (htp_server->evhtp,
                        GET_COMMIT_INFO_REGEX, get_commit_info_cb,
                        htp_server->seaf_session);

    evhtp_set_regex_cb (htp_server->evhtp,
                        GET_FS_OBJ_ID_REGEX, get_fs_obj_id_cb,
                        htp_server->seaf_session);

    evhtp_set_regex_cb (htp_server->evhtp,
                        GET_BLOCKT_REGEX, get_block_cb,
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

    evhtp_set_gencb (htp_server->evhtp, default_cb, NULL);

    get_request_init (htp_server);

    event_base_loop (htp_server->evbase, 0);

    evhtp_unbind_socket (htp_server->evhtp);
    evhtp_free (htp_server->evhtp);
    event_base_free (htp_server->evbase);
    return NULL;
}

HttpServer *
seaf_http_server_new (struct _SeafileSession *session)
{
    HttpServer *http_server = g_new0 (HttpServer, 1);
    http_server->evbase = NULL;
    http_server->evhtp = NULL;
    http_server->thread_id = 0;
    load_http_config (http_server, session);
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

