/*
 gui-mainwindows.c : irssi

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

#include "windows.h"
#include "gui-mainwindows.h"

GList *mainwindows;

MAIN_WINDOW_REC *gui_mainwindow_create(void)
{
    MAIN_WINDOW_REC *window;

    window = g_new0(MAIN_WINDOW_REC, 1);
    mainwindows = g_list_append(mainwindows, window);

    return window;
}

void gui_mainwindow_destroy(MAIN_WINDOW_REC *window)
{
    g_return_if_fail(window != NULL);
    if (window->destroying) return;

    mainwindows = g_list_remove(mainwindows, window);

    window->destroying = TRUE;
    while (window->children != NULL)
        window_destroy(window->children->data);
    window->destroying = FALSE;

    g_free(window);

    if (mainwindows == NULL)
        signal_emit("gui exit", 0);
}

void gui_mainwindows_init(void)
{
    mainwindows = NULL;
}

void gui_mainwindows_deinit(void)
{
    while (mainwindows != NULL)
        gui_mainwindow_destroy(mainwindows->data);
}
