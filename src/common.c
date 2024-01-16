#include <string.h>
#include <stdlib.h>
#include "common.h"

char *strdup(const char *s)
{
    char *dst = malloc(strlen(s) + 1);
    if (!dst)
        return NULL;

    strcpy(dst, s);
    return dst;
}
