#ifndef __PERL_CORE_H
#define __PERL_CORE_H

typedef struct {
	char *name; /* unique name */
        char *package; /* package name */

        /* Script can be loaded from a file, or from some data in memory */
	char *path; /* FILE: full path for file */
	char *data; /* DATA: data used for the script */
} PERL_SCRIPT_REC;

extern GSList *perl_scripts;

/* Initialize perl interpreter */
void perl_scripts_init(void);
/* Destroy all perl scripts and deinitialize perl interpreter */
void perl_scripts_deinit(void);

/* Load a perl script, path must be a full path. */
PERL_SCRIPT_REC *perl_script_load_file(const char *path);
/* Load a perl script from given data */
PERL_SCRIPT_REC *perl_script_load_data(const char *data);
/* Unload perl script */
void perl_script_unload(PERL_SCRIPT_REC *script);

/* Find loaded script by name */
PERL_SCRIPT_REC *perl_script_find(const char *name);
/* Find loaded script by package */
PERL_SCRIPT_REC *perl_script_find_package(const char *package);

/* Returns full path for the script */
char *perl_script_get_path(const char *name);
/* Modify the script name so that all non-alphanumeric characters are
   translated to '_' */
void script_fix_name(char *name);

/* If core should handle printing script errors */
void perl_core_print_script_error(int print);

/* Returns the perl module's API version. */
int perl_get_api_version(void);

/* Checks that the API version is correct. */
#define perl_api_version_check(library) \
	if (perl_get_api_version() != IRSSI_PERL_API_VERSION) { \
		die("Version of perl module (%d) doesn't match the " \
		    "version of "library" library (%d)", \
		    perl_get_api_version(), IRSSI_PERL_API_VERSION); \
		return; \
        }

void perl_core_init(void);
void perl_core_deinit(void);

#endif
