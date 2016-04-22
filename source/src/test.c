#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#include <logoffset.h>

int main(int argc, char *argv[])
{
    const char *fname = "test";
    long off = 3456662432425345;
    char *ret = NULL;
    time_t cur_mtime;
    time_t last_mtime;

    PGconn *conn;
    if ((conn = logpg_conn()) == NULL) {
        printf("logpg_conn failed.\n");
        exit(1);
    }

    
    cur_mtime = get_cur_mtime(fname);
    printf("cur_mtime:%s\n", ctime(&cur_mtime));

    last_mtime = get_last_mtime(conn, "loxxxg");
    printf("last_mtime:%s\n", ctime(&last_mtime));

/*
    printf("set_offset: %ld\n", off);
    if ((ret = set_offset(conn, fname, off)) != NULL) {
        printf("done set_offset(%d): %s\n", (int) strlen(ret), ret);
        free(ret);
    }

    off = get_offset(conn, fname);
    printf("get_offset: %ld\n", off);
*/

    return 0;
}
