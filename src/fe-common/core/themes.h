#ifndef __THEMES_H
#define __THEMES_H

#define THEME_FLAG_BG_SCROLLABLE        0x0001
#define THEME_FLAG_BG_SCALED            0x0002
#define THEME_FLAG_BG_SHADED            0x0004

typedef struct
{
	char *name;

	char **formatlist;
	char **format;
}
MODULE_THEME_REC;

typedef struct {
	char *path;
	char *name;

	int default_color;
	char *bg_pixmap;
	char *font;
	int flags;

	GHashTable *modules;

	gpointer gui_data;
} THEME_REC;

extern GSList *themes;
extern THEME_REC *current_theme;

THEME_REC *theme_create(const char *path, const char *name);
void theme_destroy(THEME_REC *rec);

void themes_init(void);
void themes_deinit(void);

#endif
