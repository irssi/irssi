#ifndef __PRINTTEXT_H
#define __PRINTTEXT_H

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

/* printformat(...) = printformat_format(module_formats, ...)

   Could this be any harder? :) With GNU C compiler and C99 compilers,
   use #define. With others use either inline functions if they are
   supported or static functions if they are not..
 */
#ifdef __GNUC__
/* GCC */
#  define printformat(server, channel, level, formatnum...) \
	printformat_format(MODULE_FORMATS, server, channel, level, ##formatnum)
#elif defined (_ISOC99_SOURCE)
/* C99 */
#  define printformat(server, channel, level, formatnum, ...) \
	printformat_format(MODULE_FORMATS, server, channel, level, formatnum, __VA_ARGS__)
#else
/* inline/static */
#ifdef G_CAN_INLINE
inline
#else
static
#endif
void printformat(void *server, const char *channel, int level, int formatnum, ...)
{
        printformat_format(MODULE_FORMATS, server, channel, level, ##formatnum);
}
#endif
void printformat_format(FORMAT_REC *formats, void *server, const char *channel, int level, int formatnum, ...);

void printtext(void *server, const char *channel, int level, const char *str, ...);
void printtext_multiline(void *server, const char *channel, int level, const char *format, const char *text);
void printbeep(void);

void printtext_init(void);
void printtext_deinit(void);

#endif
