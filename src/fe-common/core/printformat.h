/* printformat(...) = printformat_format(module_formats, ...)

   Could this be any harder? :) With GNU C compiler and C99 compilers,
   use #define. With others use either inline functions if they are
   supported or static functions if they are not..
 */
#if defined (__GNUC__) && !defined (__STRICT_ANSI__)
/* GCC */
#  define printformat(server, channel, level, formatnum...) \
	printformat_format(MODULE_FORMATS, server, channel, level, ##formatnum)
#elif defined (_ISOC99_SOURCE)
/* C99 */
#  define printformat(server, channel, level, formatnum, ...) \
	printformat_format(MODULE_FORMATS, server, channel, level, formatnum, __VA_ARGS__)
#else
/* inline/static */
static
#ifdef G_CAN_INLINE
inline
#endif
void printformat(void *server, const char *channel, int level, int formatnum, ...)
{
        printformat_format(MODULE_FORMATS, server, channel, level, formatnum);
}
#endif
