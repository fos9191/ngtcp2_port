#include <stdio.h>
#include <stdarg.h>

void log_printf(void *user_data, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}