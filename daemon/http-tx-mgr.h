#ifndef HTTP_TX_MGR_H
#define HTTP_TX_MGR_H

enum {
    HTTP_TASK_TYPE_DOWNLOAD = 0,
    HTTP_TASK_TYPE_UPLOAD,
};


/**
 * The state that can be set by user.
 *
 * A task in NORMAL state can be canceled;
 * A task in RT_STATE_FINISHED can be removed.
 */
enum HttpTaskState {
    HTTP_TASK_STATE_NORMAL = 0,
    HTTP_TASK_STATE_CANCELED,
    HTTP_TASK_STATE_FINISHED,
    HTTP_TASK_STATE_ERROR,
    N_HTTP_TASK_STATE,
};

enum TaskRuntimeState {
    HTTP_TASK_RT_STATE_INIT = 0,
    HTTP_TASK_RT_STATE_CHECK,
    HTTP_TASK_RT_STATE_COMMIT,
    HTTP_TASK_RT_STATE_FS,
    HTTP_TASK_RT_STATE_CHECK_BLOCKS,
    HTTP_TASK_RT_STATE_BLOCK,
    HTTP_TASK_RT_STATE_UPDATE_BRANCH, /* Only used in upload. */
    HTTP_TASK_RT_STATE_FINISHED,
    HTTP_TASK_RT_STATE_NETDOWN,
    N_HTTP_TASK_RT_STATE,
};

enum TaskError {
    HTTP_TASK_OK = 0,

    N_HTTP_TASK_ERROR,
};

struct _SeafileSession;
struct _HttpTxPriv;

struct _HttpTxManager {
    struct _SeafileSession   *seaf;

    /* Sent/recv bytes from all tasks in this second. */
    gint             sent_bytes;
    gint             recv_bytes;
    /* Upload/download rate limits. */
    gint             upload_limit;
    gint             download_limit;

    struct _HttpTxPriv *priv;
};

typedef struct _HttpTxManager HttpTxManager;

struct _HttpTxTask {
    HttpTxManager *manager;

    char repo_id[37];
    int repo_version;
    char *token;
    int protocol_version;
    int type;
    char *host;
    gboolean is_clone;

    char head[41];

    char *passwd;
    char *worktree;

    int state;
    int runtime_state;
    int error;
};
typedef struct _HttpTxTask HttpTxTask;

HttpTxManager *
http_tx_manager_new (struct _SeafileSession *seaf);

int
http_tx_manager_start (HttpTxMananger *mgr);

int
http_tx_manager_add_download (HttpTxManager *manager,
                              const char *repo_id,
                              int repo_version,
                              const char *host,
                              const char *token,
                              const char *passwd,
                              const char *worktree,
                              GError **error);

int
http_tx_manager_add_upload (HttpTxManager *manager,
                            const char *repo_id,
                            int repo_version,
                            const char *host,
                            const char *token,
                            GError **error);

struct _HttpHeadCommit {
    gboolean is_corrupt;
    gboolean is_deleted;
    char head_commit[41];
};
typedef struct _HttpHeadCommit HttpHeadCommit;

typedef void (*HttpHeadCommitCallback) (gboolean success,
                                        HttpHeadCommit *result,
                                        void *user_data);

/* Asynchronous interface for getting head commit info from a server. */
int
http_tx_manager_check_head_commit (HttpTxManager *manager,
                                   const char *repo_id,
                                   int repo_version,
                                   const char *host,
                                   const char *token,
                                   HttpHeadCommitCallback callback,
                                   void *user_data);

GList*
http_tx_manager_get_upload_tasks (HttpTxManager *manager);

GList*
http_tx_manager_get_download_tasks (HttpTxManager *manager);

void
http_tx_manager_remove_task (HttpTxManager *manager,
                             const char *repo_id,
                             int task_type);

void
http_tx_manager_cancel_task (HttpTxManager *manager,
                             const char *repo_id,
                             int task_type);

#endif
