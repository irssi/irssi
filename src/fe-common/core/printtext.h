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

void printformat_format(FORMAT_REC *formats, void *server, const char *channel, int level, int formatnum, ...);

void printtext(void *server, const char *channel, int level, const char *str, ...);
void printtext_multiline(void *server, const char *channel, int level, const char *format, const char *text);
void printbeep(void);

/* strip all color (etc.) codes from `input'. returns newly allocated string. */
char *strip_codes(const char *input);

void printtext_init(void);
void printtext_deinit(void);

#endif
