#ifndef __COMMON_SETUP_H
#define __COMMON_SETUP_H

#define DCC_FILE_CREATE_MODE 0644
#define LOG_FILE_CREATE_MODE 0644
#define CMD_CHAR '/'

/* How often to check if there's anyone to be unignored in autoignore list */
#define AUTOIGNORE_TIMECHECK 10000

/* How often to check if there's anyone to be unbanned in knockout list */
#define KNOCKOUT_TIMECHECK 10000

/* How often to check users in notify list */
#define NOTIFY_TIMECHECK 30000

/* How often to check for gone status of nick */
#define MAX_GONE_REFRESH_TIME 300

/* Maximum time to wait for more JOINs before sending massjoin signal */
#define MAX_MASSJOIN_WAIT 5000

/* lists */
extern GList *aliases, *ignores, *completions, *notifies, *hilights;

/* look and feel */
extern gboolean toggle_show_menubar;
extern gboolean toggle_show_toolbar;
extern gboolean toggle_show_statusbar;
extern gboolean toggle_show_nicklist;
extern gboolean toggle_show_timestamps;
extern gboolean toggle_hide_text_style;
extern gboolean toggle_bell_beeps;
extern gboolean toggle_actlist_moves;
extern gboolean toggle_privmsg_beeps;

extern gboolean toggle_use_status_window;
extern gboolean toggle_use_msgs_window;
extern gboolean toggle_autoraise_msgs_window;
extern gboolean toggle_autocreate_query;
extern gboolean toggle_notifylist_popups;
extern gboolean toggle_use_tabbed_windows;
extern gint tab_orientation;

/* misc */
extern gchar *url_www_client;
extern gchar *url_ftp_client;
extern gchar *url_mail_client;

extern gchar *ctcp_version_reply;
extern gchar *default_quit_message;
extern gchar *default_user_mode;

extern gint max_command_history;
extern gint max_textwidget_lines;
extern gint rawlog_lines;
extern gint block_remove_lines;

extern gint min_lag_check_time;
extern gint max_lag_before_disconnect;

extern gint knockout_time; /* How many seconds to keep /knockouted ban */
extern gboolean check_irssi_versions; /* Check if there's new irssi version available */

/* nick completion */
extern gchar *completion_char;
extern gboolean completion_disable_auto;
extern gint completion_keep_publics;
extern gint completion_keep_ownpublics;
extern gint completion_keep_privates;

/* flood protection */
extern gint flood_timecheck; /* Flood check timeout */
extern gint flood_max_msgs; /* Max msgs in FLOOD_TIMECHECK msecs before considered as flooding */
extern gint autoignore_time; /* How many seconds to keep someone autoignored */
extern gint ctcp_timecheck; /* CTCP reply send timeout */
extern gint max_ctcp_queue; /* Max CTCP reply queue length */
extern gint cmd_queue_speed; /* Minimum timeout before sending the next command to server */

/* dcc */
extern gboolean toggle_dcc_autodisplay_dialog;
extern gboolean toggle_dcc_autoget;
extern gboolean toggle_dcc_autorename;
extern gint dcc_max_autoget_size;
extern gchar *dcc_download_path;

extern gboolean toggle_dcc_fast_send;
extern gchar *dcc_upload_path;

extern gboolean toggle_dcc_mirc_ctcp;
extern gint dcc_block_size;
extern gint dcc_port;
extern gint dcc_timeout;

/* servers */
typedef struct
{
    gchar *server;
    gchar *ircnet;
    gchar *password;
    gint port;
    gboolean autoconnect;
    gint cmd_queue_speed; /* override the default if > 0 */
    time_t last_connect; /* to avoid reconnecting too fast.. */
}
SETUP_SERVER_REC;

extern GList *setupservers; /* list of local servers */
extern GList *ircnets; /* list of available ircnets */
extern gint server_reconnect_time; /* reconnect to server no sooner than n seconds */
extern gchar *source_host; /* Our own IP to use */
extern gboolean source_host_ok; /* Use source_host_ip .. */
extern IPADDR source_host_ip; /* Resolved address */
extern gchar *default_nick, *alternate_nick, *user_name, *real_name;
extern gboolean toggle_skip_motd;

/* channels */
typedef struct
{
    gboolean autojoin;
    gchar *name;
    gchar *ircnet;
    gchar *password;

    gchar *botmasks;
    gchar *autosendcmd;

    gchar *background;
    gchar *font;
}
SETUP_CHANNEL_REC;

extern GList *setupchannels;

/* IRC proxy */
extern gboolean toggle_use_ircproxy;
extern gchar *proxy_address;
extern gint proxy_port;
extern gchar *proxy_string;

/* appearance */
extern gboolean toggle_buggy_gtkthemes;
extern gboolean toggle_use_itext;
extern gboolean toggle_background_transparent;
extern gint panel_max_channels;

#endif
