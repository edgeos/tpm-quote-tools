
#if defined HAVE_CONFIG_H
#include "config.h"
#endif

#if defined HAVE_ICONV_H

#include <stdlib.h>

#if HAVE_LANGINFO_H
#include <langinfo.h>
#endif

char *get_codeset(void) 
{
    char * codeset;

#if HAVE_LANGINFO_H
    codeset = nl_langinfo(CODESET);
#else
    codeset = getenv("LC_ALL");
    if (codeset == NULL || codeset[0] == '\0') {
        codeset = getenv("LC_CTYPE");
        if (codeset == NULL || codeset[0] == '\0') {
            codeset = getenv("LANG");
        }    
    }    
#endif

    /* Do not return NULL */
    if (codeset == NULL || codeset[0] == '\0') {
        codeset = "ASCII";
    }

    return codeset;
}

#endif
