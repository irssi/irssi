/*
 gui-statusbar.c : irssi

    Copyright (C) 1999 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "server.h"

#include "windows.h"

#include "screen.h"
#include "gui-statusbar.h"
#include "gui-mainwindows.h"
#include "gui-windows.h"

typedef struct
{
    gint tag;

    gint xpos, ypos;
    gint size;
    gboolean right_justify, up;
    STATUSBAR_FUNC func;
}
STATUSBAR_REC;

static GList *sbars;
static gint sbars_tag;

static void gui_statusbar_redraw_line(gboolean up, gint ypos)
{
    GList *tmp;
    gint xpos, rxpos;

    xpos = 1;
    for (tmp = sbars; tmp != NULL; tmp = tmp->next)
    {
        STATUSBAR_REC *rec = tmp->data;

        if (!rec->right_justify)
        {
            if (rec->up == up && rec->ypos == ypos && xpos+rec->size < COLS)
            {
                rec->xpos = xpos;
		rec->func(xpos, rec->ypos + (rec->up ? 0 : last_text_line), rec->size);
                if (rec->size > 0) xpos += rec->size+1;
            }
        }
    }

    rxpos = COLS-1;
    for (tmp = sbars; tmp != NULL; tmp = tmp->next)
    {
        STATUSBAR_REC *rec = tmp->data;

        if (rec->right_justify)
        {
            if (rec->up == up && rec->ypos == ypos && rxpos-rec->size > xpos)
            {
                rec->xpos = rxpos-rec->size;
		rec->func(rec->xpos, rec->ypos + (rec->up ? 0 : last_text_line), rec->size);
                if (rec->size > 0) rxpos -= rec->size+1;
            }
        }
    }
}

static void gui_statusbar_redraw_all(void)
{
    gint n;

    screen_refresh_freeze();
    set_bg((1<<4)+15);
    for (n = 0; n < first_text_line; n++)
    {
	move(n, 0); clrtoeol();
    }
    for (n = last_text_line; n < LINES-1; n++)
    {
	move(n, 0); clrtoeol();
    }
    set_bg(0);

    for (n = 0; n < LINES-1; n++)
    {
	gui_statusbar_redraw_line(FALSE, n);
	gui_statusbar_redraw_line(TRUE, n);
    }
    screen_refresh_thaw();
}

void gui_statusbar_redraw(gint tag)
{
    GList *tmp;

    if (tag == -1)
    {
        gui_statusbar_redraw_all();
        return;
    }

    for (tmp = sbars; tmp != NULL; tmp = tmp->next)
    {
        STATUSBAR_REC *rec = tmp->data;

        if (rec->tag == tag)
	{
	    rec->func(rec->xpos, rec->ypos + (rec->up ? 0 : last_text_line), rec->size);
            break;
        }
    }
}

/* create new statusbar, return position */
gint gui_statusbar_create(gboolean up)
{
    gint pos;

    pos = up ? first_text_line++ :
	(LINES-2)-last_text_line--;

    set_bg((1<<4)+15);
    move(up ? pos : last_text_line+pos, 0); clrtoeol();
    set_bg(0);

    gui_windows_resize(-1, FALSE);
    return pos;
}

void gui_statusbar_delete(gboolean up, gint ypos)
{
    GList *tmp, *next;

    if (up && first_text_line > 0)
	first_text_line--;
    else if (!up && last_text_line < LINES-1)
	last_text_line++;

    for (tmp = sbars; tmp != NULL; tmp = next)
    {
        STATUSBAR_REC *rec = tmp->data;

	next = tmp->next;
	if (rec->up == up && rec->ypos == ypos)
	    gui_statusbar_remove(rec->tag);
	else if (rec->up == up && rec->ypos > ypos)
            rec->ypos--;
    }

    gui_windows_resize(1, FALSE);
}

/* allocate area in statusbar, returns tag or -1 if failed */
gint gui_statusbar_allocate(gint size, gboolean right_justify, gboolean up, gint ypos, STATUSBAR_FUNC func)
{
    STATUSBAR_REC *rec;

    g_return_val_if_fail(func != NULL, -1);

    rec = g_new0(STATUSBAR_REC, 1);
    sbars = g_list_append(sbars, rec);

    rec->tag = ++sbars_tag;
    rec->xpos = -1;
    rec->up = up;
    rec->ypos = ypos;
    rec->size = size;
    rec->right_justify = right_justify;
    rec->func = func;

    gui_statusbar_redraw_all();
    return rec->tag;
}

void gui_statusbar_resize(gint tag, gint size)
{
    GList *tmp;

    for (tmp = sbars; tmp != NULL; tmp = tmp->next)
    {
        STATUSBAR_REC *rec = tmp->data;

        if (rec->tag == tag)
        {
            rec->size = size;
            gui_statusbar_redraw_all();
            break;
        }
    }
}

void gui_statusbar_remove(gint tag)
{
    GList *tmp;

    for (tmp = sbars; tmp != NULL; tmp = tmp->next)
    {
        STATUSBAR_REC *rec = tmp->data;

        if (rec->tag == tag)
        {
            g_free(rec);
            sbars = g_list_remove(sbars, rec);
            if (!quitting) gui_statusbar_redraw_all();
            break;
        }
    }
}

void gui_statusbar_init(void)
{
    sbars = NULL;
    sbars_tag = 0;

    gui_statusbar_create(FALSE);
}

void gui_statusbar_deinit(void)
{
    gui_statusbar_delete(FALSE, 0);
}
