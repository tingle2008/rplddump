#include <rplddump.h>

void myfree(void **p)
{
    if (*p != NULL) {
        free(*p);
    }
    *p = NULL;

    return;
}

int myrm(const char *name)
{
    char *buf   = NULL;
    int  namelen = 0;
    int  rmlen = 0;
    int  ret    = -1;

#define MYRM "rm -rf "

    namelen = strlen(name);
    rmlen   = strlen(MYRM);

    buf = malloc(namelen+rmlen+1);
    memset(buf, 0, namelen+rmlen+1);
    strncpy(buf, MYRM, rmlen);
    buf[rmlen] = '\0';
    strncat(buf, name, namelen);
    buf[namelen+rmlen] = '\0';

    ret = system(buf);
    free(buf);
    return ret;
}
