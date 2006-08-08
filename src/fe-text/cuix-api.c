#include "module.h"
#include "settings.h"
#include "term.h"
#include "gui-windows.h"
#include <stdarg.h>
#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif
#include <form.h>
#include <panel.h>
#include <menu.h>


#include "cuix-api.h"

#define INIT_ENTRIES 8
#define X0_OFFSET 4
#define Y0_OFFSET 2
#define Y_OFFSET 1
#define CUIX_FIELD_WIDTH 16

object *create_object (char *title, int type, void **entries)
{
    object *obj;
    void **new_entries;
    int i;

    obj = g_malloc (sizeof(object));
    if (!obj) {
        return NULL;
    }
    obj->type = type;
    obj->title = title;
    if (!entries) {
        new_entries = g_new0 (void *, INIT_ENTRIES);
        obj->entries = new_entries;
        obj->alloced = INIT_ENTRIES;
        obj->last = 0;
    } else {
        for (i = 0; ((entry **)entries)[i]; i++);
        obj->alloced = i;
        obj->last = i;
        obj->entries = entries;
    }
    return obj;
}


object *create_menu (char *title)
{
    return create_object (title, CUIX_MENU, NULL);
}


object *create_form (char *title)
{
    return create_object (title, CUIX_FORM, NULL);
}


/* entries must be NULL terminated */
object *create_list (char *title, entry **entries)
{
    return create_object (title, CUIX_LIST, (void **)entries);
}

entry *create_entry (char *label, int type, action_fn_type action)
{
    entry *entry;
    
    entry = g_malloc (sizeof(object));
    if (!entry) {
        return NULL;
    }
    entry->type = type;
    entry->data = label;
    entry->action = action;
    return entry;
}

entry *create_menuentry (char *label, action_fn_type action)
{
    return create_entry (label, CUIX_MENUENTRY, action);
}

entry *create_label (char *label)
{
    return create_entry (label, CUIX_LABEL, NULL);
}


entry *create_field (char *label, action_fn_type action)
{
    return create_entry (label, CUIX_FIELD, action);
}



/* Adds child at the last position of father->entries */
void attach_entry (object *father, void *child)
{
    void **entries;
    int i;

    /* Check that we have enough space in father->entries, otherwise alloc
     * twice more than previously */
    if (father->last >= father->alloced) {
        entries = g_new0 (void *,2 * father->alloced);
        if (!entries) {
            fprintf (stderr, "Problem with memory allocation, quitting now...\n");
            exit (1);
        }
        for (i = 0; i < father->alloced; i++) {
            entries[i] = father->entries[i];
        }
        g_free (father->entries);
        father->entries = entries;
        father->alloced *= 2;
    }
    father->entries[father->last++] = child;
}


/* Adds a submenu to father */
void attach_submenu (object *father, object *child)
{ 

    /* Check that both are really menus */
    if (father->type != CUIX_MENU || child->type != CUIX_MENU) {
        fprintf (stderr, "Typing error, trying to add %p (%d) as child of"
                "%p (%d)\n", father, father->type, child, child->type);
        exit (1);
    }
    attach_entry (father, (void *)child);
}


/* Returns the maximum width occupied by labels */
int get_labels_width (object *obj)
{
    int i;
    unsigned int w = 0;
    entry *e;
    object *o;

    for (i = 0; i < obj->last; i++) {
        e = (entry *)obj->entries[i];
        if (e->type == CUIX_LABEL || e->type == CUIX_MENUENTRY) {
            w = (w > strlen (e->data)) ? w : strlen (e->data);
        }
        if (e->type == CUIX_MENU) {
            o = (object *)obj->entries[i];
            w = (w > strlen (o->title)) ? w : strlen (o->title);
        }

    }
    w += 2 * X0_OFFSET;
    return (int)w;
}


/* Puts in x and y the coordinates to center an object of size objw and objh
 * in the window win */
void get_center (WINDOW *win, int objh, int objw, int *y, int *x)
{
    int begx, begy, maxx, maxy, w, h;
    getbegyx (win, begy, begx);
    getmaxyx (win, maxy, maxx);
    w = maxx - begx;
    h = maxy - begy;
    *x = (w - objw) / 2 + begx;
    *y = (h - objh) / 2 + begy;
    if (*x < 0)
        *x = 0;
    if (*y < 0)
        *y = 0;
}



void display_object (object *obj)
{
    WINDOW *subwin;
    FORM *form;
    MENU *menu;
    FIELD **fields;
    ITEM **items, *cur_item;
    object *o;
    entry *e;
    char *result;
    int i, x, y, w, h;
    int ch;
    p_main = new_panel(root_window->win);

    if (obj->type >= CUIX_LABEL) {
        fprintf (stderr, "Trying to display an entry %p (%d), terminating...\n",
                obj, obj->type);
        exit (1);
    }

    switch (obj->type) {
        case CUIX_LIST:
            w = get_labels_width (obj);
            h = Y_OFFSET * obj->last + 2 * Y0_OFFSET;
            get_center (root_window->win, h, w, &y, &x);
            cuix_win = newwin (h, w, y, x);
            box (cuix_win, 0, 0);
            p_cuix = new_panel(cuix_win);
            x = X0_OFFSET;
            y = Y0_OFFSET;

            for (i = 0; i < obj->last; i++) {
                e = (entry *)obj->entries[i];
                if (e->type != CUIX_LABEL) {
                    fprintf (stderr, "Non-label entry in a list.\n");
                    exit (1);
                } 
                wmove (cuix_win,y,x);
                waddstr (cuix_win,e->data);
                y += Y_OFFSET;
                x = X0_OFFSET;
            }
            top_panel (p_cuix);
            update_panels();
            doupdate();
            wgetch(cuix_win);
            /* refresh (); */
            /* wrefresh (cuix_win); */
            break;

        case CUIX_FORM:
            w = get_labels_width (obj);
            w = (w > CUIX_FIELD_WIDTH + 2 * X0_OFFSET) ?
                w : CUIX_FIELD_WIDTH + 2 * X0_OFFSET;
            h = Y_OFFSET * obj->last + 2 * Y0_OFFSET;
            fields = g_new0 (FIELD *, obj->last + 1);
            for (i = 0; i < obj->last; i++) {
                e = (entry *)obj->entries[i];
                fields[i] = new_field (1, w,
                        Y0_OFFSET + i * Y_OFFSET, X0_OFFSET, 0, 0);
                if (e->type == CUIX_LABEL) {
                    field_opts_off (fields[i], O_ACTIVE);
                    field_opts_off (fields[i], O_EDIT);
                    set_field_back  (fields[i], A_BOLD);
                }
                set_field_buffer (fields[i], 0, e->data);
            }
            fields[obj->last] = NULL;
            form = new_form (fields);
            scale_form (form, &h, &w);
            h += Y0_OFFSET;
            w += 2 * X0_OFFSET;
            get_center (root_window->win, h, w, &y, &x);
            cuix_win = newwin (h, w, y, x);
            keypad (cuix_win, TRUE);
            nonl ();
            set_form_win (form, cuix_win);
            set_form_sub (form, derwin(cuix_win, w, h, X0_OFFSET, Y0_OFFSET));
            post_form (form);
            box (cuix_win, 0, 0);
            p_cuix = new_panel (cuix_win);
            top_panel (p_cuix);
            while((ch = wgetch(cuix_win)) != '\n' && ch != '\r' && ch != 27 /* ESC */) {       
                switch(ch) {       
                    case KEY_DOWN:
                        /* Go to next field */
                        form_driver(form, REQ_NEXT_FIELD);
                        /* Go to the end of the present buffer */
                        /* Leaves nicely at the last character */
                        form_driver(form, REQ_END_LINE);
                        break;
                    case KEY_UP:
                        /* Go to previous field */
                        form_driver(form, REQ_PREV_FIELD);
                        form_driver(form, REQ_END_LINE);
                        break;
                    case KEY_BACKSPACE:
                        form_driver(form, REQ_PREV_CHAR);
                        form_driver(form, REQ_DEL_CHAR);
                        break;
                    case KEY_LEFT:
                        form_driver(form, REQ_PREV_CHAR);
                        break;
                    case KEY_RIGHT:
                        form_driver(form, REQ_NEXT_CHAR);
                        break;
                    default:
                        /* If this is a normal character, it gets */
                        /* Printed                                */    
                        form_driver(form, ch);
                        break;
                }
            }
            form_driver (form, REQ_VALIDATION);
            if (ch != 27) {
                for (i = 0; i < obj->last; i++) {
                    e = (entry *)obj->entries[i];
                    if (e->type == CUIX_FIELD) {
                        result = field_buffer(fields[i],0);
                        e->action (result);
                    }
                }
            }
            for (i = 0; i < obj->last; i++) {
                free_field (fields[i]);
            }
            g_free (fields);
            unpost_form (form);

            break;

        case CUIX_MENU:
            w = get_labels_width (obj);
            w = (w > CUIX_FIELD_WIDTH + 2 * X0_OFFSET) ?
                w : CUIX_FIELD_WIDTH + 2 * X0_OFFSET;
            h = Y_OFFSET * obj->last + 2 * Y0_OFFSET;
            items = g_new0 (ITEM *, obj->last + 1);
            for (i = 0; i < obj->last; i++) {
                e = (entry *)obj->entries[i];
                o = (object *)obj->entries[i];
                if (e->type == CUIX_MENUENTRY) {
                    items[i] = new_item (e->data, "");
                    set_item_userptr (items[i], (void*)e);
                } else {
                    if (e->type == CUIX_LABEL) {
                        items[i] = new_item (e->data, "");
                        item_opts_off (items[i], O_SELECTABLE);
                    } else {
                        items[i] = new_item (o->title, " (SUB) ");
                        set_item_userptr (items[i], (void*)o);
                    }
                }
            }
            items[obj->last] = NULL;
            menu = new_menu (items);
            set_menu_mark (menu, " * ");
            scale_menu (menu, &h, &w);
            h += 4 * Y0_OFFSET;
            w += 4 * X0_OFFSET;
            get_center (root_window->win, h, w, &y, &x);
             cuix_win = newwin (h, w, y, x);
            keypad (cuix_win, TRUE);
            nonl ();
            set_menu_win (menu, cuix_win);
            subwin = derwin (cuix_win,
                    h - 2 * Y0_OFFSET, w - 2 * X0_OFFSET, Y0_OFFSET, X0_OFFSET);
            set_menu_sub (menu, subwin);
            box (cuix_win, 0, 0);
            post_menu (menu);
            p_cuix = new_panel (cuix_win);
            top_panel (p_cuix);
            while((ch = wgetch(cuix_win)) != 27 /* ESC */) {       
                switch(ch) {       
                    case KEY_DOWN:
                        menu_driver(menu, REQ_DOWN_ITEM);
                        break;
                    case KEY_UP:
                        menu_driver(menu, REQ_UP_ITEM);
                        break;
                    case '\n':
                    case '\r':
                        cur_item = current_item(menu);
                        e = (entry *)item_userptr(cur_item);
                        o = (object *)item_userptr(cur_item);
                        if (e->type == CUIX_MENUENTRY)
                        {
                            e->action ("");
                        } else {
                            display_object (o);
                        }
                        goto end;
                        break;
                    default:
                        break;
                }
            }
end:
            for (i = 0; i < obj->last; i++) {
                free_item (items[i]);
            }
            g_free (items);
            unpost_menu (menu);
    }
}
