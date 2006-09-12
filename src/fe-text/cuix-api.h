#ifndef __CUIX_API_H
#define __CUIX_API_H

#include "term-curses.h"

#define MAX_FIELD_SIZE 64

WINDOW *cuix_win;
PANEL *p_main;
PANEL *p_cuix;

enum objtype {
    /* For objects */
    CUIX_MENU,
    CUIX_FORM,
    CUIX_LIST,
    /* For entries */
    /* NB: LABEL must stay the first entry, as it is used to test if we have
     * an object or an entry */
    CUIX_LABEL,
    CUIX_FIELD,
    CUIX_MENUENTRY
};



/* This is the type of the action to be executed when the entry has been
 * successfully selected (in case of a menuentry) or filled (in case of a
 * field). */
typedef int(*action_fn_type)(char *);


typedef struct entry {
    int type;
    char *data; /* contains label or submenu title */
    action_fn_type action;
} entry;


typedef struct object {
    int type;
    char *title;
    void **entries;
    int alloced; /* defines the current size of entries */ 
    int last; /* index of the first non-alloced entry */
} object;


/* Object definitions */

object *create_menu (char *title);
object *create_form (char *title);
/* entries must be NULL terminated */
object *create_list (char *title, entry **entries);


entry *create_menuentry (char *label, action_fn_type action);
entry *create_label (char *label);
entry *create_field (char *label, action_fn_type action);

void attach_submenu (object *father, object *child);
void attach_entry (object *father, void *child);

void display_object (object *obj);

void my_menu(void);

#endif /* __CUIX_API_H */
