#ifndef __PRINTTEXT_H
#define __PRINTTEXT_H

#include "windows.h"

enum {
	FORMAT_STRING,
	FORMAT_INT,
	FORMAT_LONG,
	FORMAT_FLOAT
};

typedef struct {
	char *tag;
	char *def;

	int params;
	int paramtypes[10];
} FORMAT_REC;

#define PRINTFLAG_BOLD          0x01
#define PRINTFLAG_REVERSE       0x02
#define PRINTFLAG_UNDERLINE     0x04
#define PRINTFLAG_BEEP          0x08
#define PRINTFLAG_BLINK         0x10
#define PRINTFLAG_MIRC_COLOR    0x20
#define PRINTFLAG_INDENT        0x40

char *output_format_get_text(const char *module, WINDOW_REC *window,
			     void *server, const char *channel,
			     int formatnum, ...);

void printformat_module(const char *module, void *server, const char *channel, int level, int formatnum, ...);
void printformat_module_window(const char *module, WINDOW_REC *window, int level, int formatnum, ...);

void printformat_module_args(const char *module, void *server, const char *channel, int level, int formatnum, va_list va);
void printformat_module_window_args(const char *module, WINDOW_REC *window, int level, int formatnum, va_list va);

void printtext(void *server, const char *channel, int level, const char *text, ...);
void printtext_window(WINDOW_REC *window, int level, const char *text, ...);
void printtext_multiline(void *server, const char *channel, int level, const char *format, const char *text);
void printbeep(void);

/* strip all color (etc.) codes from `input'. returns newly allocated string. */
char *strip_codes(const char *input);

void printtext_init(void);
void printtext_deinit(void);

/* printformat(...) = printformat_format(MODULE_NAME, ...)

   Could this be any harder? :) With GNU C compiler and C99 compilers,
   use #define. With others use either inline functions if they are
   supported or static functions if they are not..
 */
#if defined (__GNUC__) && !defined (__STRICT_ANSI__)
/* GCC */
#  define printformat(server, channel, level, formatnum...) \
	printformat_module(MODULE_NAME, server, channel, level, ##formatnum)
#  define printformat_window(window, level, formatnum...) \
	printformat_module_window(MODULE_NAME, window, level, ##formatnum)
#elif defined (_ISOC99_SOURCE)
/* C99 */
#  define printformat(server, channel, level, formatnum, ...) \
	printformat_module(MODULE_NAME, server, channel, level, formatnum, __VA_ARGS__)
#  define printformat_window(window, level, formatnum, ...) \
	printformat_module_window(MODULE_NAME, window, level, formatnum, __VA_ARGS__)
#else
/* inline/static */
static
#ifdef G_CAN_INLINE
inline
#endif
void printformat(void *server, const char *channel, int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_args(MODULE_NAME, server, channel, level, formatnum, va);
	va_end(va);
}

static
#ifdef G_CAN_INLINE
inline
#endif
void printformat_window(WINDOW_REC *window, int level, int formatnum, ...)
{
	va_list va;

	va_start(va, formatnum);
	printformat_module_window_args(MODULE_NAME, window, level, formatnum, va);
	va_end(va);
}
#endif

#endif
