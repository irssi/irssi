#ifndef IRSSI_FE_COMMON_CORE_PRINTTEXT_H
#define IRSSI_FE_COMMON_CORE_PRINTTEXT_H

#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/formats.h>

void printformat_module(const char *module, void *server, const char *target, int level, int formatnum, ...);
void printformat_module_window(const char *module, WINDOW_REC *window, int level, int formatnum, ...);
void printformat_module_dest(const char *module, TEXT_DEST_REC *dest, int formatnum, ...);

void printformat_module_args(const char *module, void *server, const char *target, int level, int formatnum, va_list va);
void printformat_module_window_args(const char *module, WINDOW_REC *window, int level, int formatnum, va_list va);
void printformat_module_dest_args(const char *module, TEXT_DEST_REC *dest, int formatnum, va_list va);
void printformat_module_dest_charargs(const char *module, TEXT_DEST_REC *dest, int formatnum, char **arglist);

void printtext(void *server, const char *target, int level, const char *text, ...);
void printtext_string(void *server, const char *target, int level, const char *text);
void printtext_string_window(WINDOW_REC *window, int level, const char *text);
void printtext_window(WINDOW_REC *window, int level, const char *text, ...);
void printtext_multiline(void *server, const char *target, int level, const char *format, const char *text);
void printtext_dest(TEXT_DEST_REC *dest, const char *text, ...);

/* only GUI should call these - used for printing text to somewhere else
   than windows */
void printtext_gui(const char *text);
void printtext_gui_internal(const char *str);
void printformat_module_gui(const char *module, int formatnum, ...);
void printformat_module_gui_args(const char *module, int formatnum, va_list va);

void printtext_init(void);
void printtext_deinit(void);

/* printformat(...) = printformat_format(MODULE_NAME, ...)

   Irssi requires a C99 pre-processor with __VA_ARGS__ support  */
#  define printformat(server, target, level, formatnum, ...) \
	printformat_module(MODULE_NAME, server, target, level, formatnum, ##__VA_ARGS__)
#  define printformat_window(window, level, formatnum, ...) \
	printformat_module_window(MODULE_NAME, window, level, formatnum, ##__VA_ARGS__)
#  define printformat_dest(dest, formatnum, ...) \
	printformat_module_dest(MODULE_NAME, dest, formatnum, ##__VA_ARGS__)
#  define printformat_gui(formatnum, ...) \
	printformat_module_gui(MODULE_NAME, formatnum, ##__VA_ARGS__)

#endif
