#ifdef MEM_DEBUG
void ig_mem_profile(void);

void ig_set_data(const char *data);

void *ig_malloc(int size, const char *file, int line);
void *ig_malloc0(int size, const char *file, int line);
void *ig_realloc(void *mem, unsigned long size, const char *file, int line);
char *ig_strdup(const char *str, const char *file, int line);
char *ig_strndup(const char *str, int count, const char *file, int line);
char *ig_strconcat(const char *file, int line, const char *str, ...);
char *ig_strdup_printf(const char *file, int line, const char *format, ...) G_GNUC_PRINTF (3, 4);
char *ig_strdup_vprintf(const char *file, int line, const char *format, va_list args);
void ig_free(void *p);
GString *ig_string_new(const char *file, int line, const char *str);
void ig_string_free(const char *file, int line, GString *str, int freeit);
char *ig_strjoinv(const char *file, int line, const char *sepa, char **array);
char *ig_dirname(const char *file, int line, const char *fname);
char *ig_module_build_path(const char *file, int line, const char *dir, const char *module);

#define g_malloc(a) ig_malloc(a, __FILE__, __LINE__)
#define g_malloc0(a) ig_malloc0(a, __FILE__, __LINE__)
#define g_free ig_free
#define g_realloc(a,b) ig_realloc(a, b, __FILE__, __LINE__)
#define g_strdup(a) ig_strdup(a, __FILE__, __LINE__)
#define g_strndup(a, b) ig_strndup(a, b, __FILE__, __LINE__)
#define g_string_new(a) ig_string_new(__FILE__, __LINE__, a)
#define g_string_free(a, b) ig_string_free(__FILE__, __LINE__, a, b)
#define g_strjoinv(a,b) ig_strjoinv(__FILE__, __LINE__, a, b)
#define g_dirname(a) ig_dirname(__FILE__, __LINE__, a)
#define g_module_build_path(a, b) ig_module_build_path(__FILE__, __LINE__, a, b)

#ifndef __STRICT_ANSI__
#define g_strconcat(a...) ig_strconcat(__FILE__, __LINE__, ##a)
#define g_strdup_printf(a, b...) ig_strdup_printf(__FILE__, __LINE__, a, ##b)
#define g_strdup_vprintf(a, b...) ig_strdup_vprintf(__FILE__, __LINE__, a, ##b)
#endif
#endif
