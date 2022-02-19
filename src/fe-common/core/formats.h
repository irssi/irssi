#ifndef IRSSI_FE_COMMON_CORE_FORMATS_H
#define IRSSI_FE_COMMON_CORE_FORMATS_H

#include <irssi/src/core/signals.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/themes.h>

#define GUI_PRINT_FLAG_BOLD          0x0001
#define GUI_PRINT_FLAG_REVERSE       0x0002
#define GUI_PRINT_FLAG_UNDERLINE     0x0004
#define GUI_PRINT_FLAG_BLINK         0x0008
#define GUI_PRINT_FLAG_MIRC_COLOR    0x0010
#define GUI_PRINT_FLAG_INDENT        0x0020
#define GUI_PRINT_FLAG_ITALIC        0x0040
#define GUI_PRINT_FLAG_NEWLINE       0x0080
#define GUI_PRINT_FLAG_CLRTOEOL      0x0100
#define GUI_PRINT_FLAG_MONOSPACE     0x0200
#define GUI_PRINT_FLAG_COLOR_24_FG   0x0400
#define GUI_PRINT_FLAG_COLOR_24_BG   0x0800

#define MAX_FORMAT_PARAMS 10
#define DEFAULT_FORMAT_ARGLIST_SIZE 200

enum {
	FORMAT_STRING,
	FORMAT_INT,
	FORMAT_LONG,
	FORMAT_FLOAT
};

struct _FORMAT_REC {
	char *tag;
	char *def;

	int params;
	int paramtypes[MAX_FORMAT_PARAMS];
};

/* clang-format off */
#define PRINT_FLAG_SET_LINE_START	0x0001
#define PRINT_FLAG_SET_LINE_START_IRSSI	0x0002
#define PRINT_FLAG_UNSET_LINE_START	0x0040

#define PRINT_FLAG_SET_TIMESTAMP	0x0004
#define PRINT_FLAG_UNSET_TIMESTAMP	0x0008

#define PRINT_FLAG_SET_SERVERTAG	0x0010
#define PRINT_FLAG_UNSET_SERVERTAG	0x0020

#define PRINT_FLAG_FORMAT         	0x0080
/* clang-format on */

typedef struct _HILIGHT_REC HILIGHT_REC;

typedef struct _TEXT_DEST_REC {
	WINDOW_REC *window;
	SERVER_REC *server;
        const char *server_tag; /* if server is non-NULL, must be server->tag */
	const char *target;
	const char *nick;
	const char *address;
	int level;

	int hilight_priority;
	char *hilight_color;
	int flags; /* PRINT_FLAG */
	GHashTable *meta;
} TEXT_DEST_REC;

typedef struct _LINE_INFO_META_REC {
	gint64 server_time;
	GHashTable *hash;
} LINE_INFO_META_REC;

#define window_get_theme(window) \
	(window != NULL && (window)->theme != NULL ? \
	(window)->theme : current_theme)

int format_find_tag(const char *module, const char *tag);

/* Return length of text part in string (ie. without % codes) */
int format_get_length(const char *str);
/* Return how many characters in `str' must be skipped before `len'
   characters of text is skipped. Like strip_real_length(), except this
   handles %codes. */
int format_real_length(const char *str, int len);

char *format_string_expand(const char *text, int *flags);
char *format_string_unexpand(const char *text, int flags);

char *format_get_text(const char *module, WINDOW_REC *window,
		      void *server, const char *target,
		      int formatnum, ...);

/* good size for buffer is DEFAULT_FORMAT_ARGLIST_SIZE */
void format_read_arglist(va_list va, FORMAT_REC *format,
			 char **arglist, int arglist_size,
			 char *buffer, int buffer_size);
char *format_get_text_theme(THEME_REC *theme, const char *module,
			    TEXT_DEST_REC *dest, int formatnum, ...);
char *format_get_text_theme_args(THEME_REC *theme, const char *module,
				 TEXT_DEST_REC *dest, int formatnum,
				 va_list va);
char *format_get_text_theme_charargs(THEME_REC *theme, const char *module,
				     TEXT_DEST_REC *dest, int formatnum,
				     char **args);

/* add `linestart' to start/end of each line in `text'. `text' may contain
   multiple lines separated with \n. */
char *format_add_linestart(const char *text, const char *linestart);
char *format_add_lineend(const char *text, const char *linestart);

/* return the "-!- " text at the start of the line */
char *format_get_level_tag(THEME_REC *theme, TEXT_DEST_REC *dest);

/* return timestamp + server tag */
char *format_get_line_start(THEME_REC *theme, TEXT_DEST_REC *dest, time_t t);


/* "private" functions for printtext */
void format_create_dest(TEXT_DEST_REC *dest,
			void *server, const char *target,
			int level, WINDOW_REC *window);
void format_create_dest_tag(TEXT_DEST_REC *dest, void *server, const char *server_tag,
                            const char *target, int level, WINDOW_REC *window);

void format_newline(TEXT_DEST_REC *dest);

/* manipulate the meta table of a dest */
void format_dest_meta_stash(TEXT_DEST_REC *dest, const char *meta_key, const char *meta_value);
const char *format_dest_meta_stash_find(TEXT_DEST_REC *dest, const char *meta_key);
void format_dest_meta_clear_all(TEXT_DEST_REC *dest);

/* Return how many characters in `str' must be skipped before `len'
   characters of text is skipped. */
int strip_real_length(const char *str, int len,
		      int *last_color_pos, int *last_color_len);

/* strip all color (etc.) codes from `input'.
   Returns newly allocated string. */
char *strip_codes(const char *input);

/* send a fully parsed text string for GUI to print */
void format_send_to_gui(TEXT_DEST_REC *dest, const char *text);
/* parse text string into GUI_PRINT_FLAG_* separated pieces and emit them to handler
   handler is a SIGNAL_FUNC with the following arguments:

   WINDOW_REC *window, void *fgcolor_int, void *bgcolor_int,
       void *flags_int, const char *textpiece, TEXT_DEST_REC *dest

 */
void format_send_as_gui_flags(TEXT_DEST_REC *dest, const char *text, SIGNAL_FUNC handler);

#define FORMAT_COLOR_NOCHANGE	('0'-1) /* don't change this, at least hilighting depends this value */
#define FORMAT_COLOR_EXT1	('0'-2)
#define FORMAT_COLOR_EXT2	('0'-3)
#define FORMAT_COLOR_EXT3	('0'-4)
#define FORMAT_COLOR_EXT1_BG	('0'-5)
#define FORMAT_COLOR_EXT2_BG	('0'-9)
#define FORMAT_COLOR_EXT3_BG	('0'-10)
#define FORMAT_COLOR_24	('0'-13)

#define FORMAT_STYLE_SPECIAL	0x60
#define FORMAT_STYLE_BLINK	(0x01 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_UNDERLINE	(0x02 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_BOLD	(0x03 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_REVERSE	(0x04 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_INDENT	(0x05 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_ITALIC	(0x06 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_DEFAULTS	(0x07 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_CLRTOEOL	(0x08 + FORMAT_STYLE_SPECIAL)
#define FORMAT_STYLE_MONOSPACE	(0x09 + FORMAT_STYLE_SPECIAL)
int format_expand_styles(GString *out, const char **format, int *flags);
void format_ext_color(GString *out, int bg, int color);
void format_24bit_color(GString *out, int bg, unsigned int color);
void format_gui_flags(GString *out, int *last_fg, int *last_bg, int *last_flags, int fg, int bg,
                      int flags);

void formats_init(void);
void formats_deinit(void);

#endif
