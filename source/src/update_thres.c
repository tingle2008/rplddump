#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "logoffset.h"

#define TH_NAME "off_lastupdate"
#define TM_SIZE 8

int get_thres(void);
int set_thres(time_t *th_new);

int main(int argc, char *argv[])
{

    int ret = -1;
    int opt = 1;
    char *endp;
    time_t th_new = -1;
    
    while ((opt = getopt(argc, argv, "gs:")) != -1) {
        switch (opt) {
            case 'g':
                ret = get_thres();
                exit(ret);
            case 's':
                th_new = (time_t)strtol(optarg, &endp, 16);
                if (optarg && endp && (*endp != '\0')) {
                    fprintf(stderr, "invalid arg '-s *%s*' for time_t.([0-9,a-f] only).\n", optarg);
                    exit(1);
                }
                ret = set_thres(&th_new);
                exit(ret);
            default:
                fprintf(stderr, "Usage: %s [-g|-s time_t]\n", argv[0]);
                exit(1);
        }
    }

    return 0;
}

int get_thres(void)
{
    PGconn *conn = NULL;
    PGresult *res = NULL;
    time_t   t_thres = -1;

    if ((conn = logpg_conn()) == NULL) {
        return -1;
    }

    if ((t_thres = get_last_mtime(conn, TH_NAME)) < 0) {
        return -1;
    }

    fprintf(stdout, "%-8lx\n", (long)t_thres);

    logpg_finish(conn);

    return 0;
}

int set_thres(time_t *th_new)
{
    int ret;
    char *str_mtime;
    PGconn *conn = NULL;
    PGresult *res = NULL;

    if ((conn = logpg_conn()) == NULL) {
        return -1;
    }

    //printf("%s\n", set_last_mtime(conn, TH_NAME, th_new));
    if ((str_mtime = set_last_mtime(conn, TH_NAME, th_new)) == NULL) {
        fprintf(stderr, "failed: %s\n", str_mtime);
        ret = -1;
    } else {
        fprintf(stdout, "done: %s\n", str_mtime);
        ret = 0;
    }

    free(str_mtime);
    logpg_finish(conn);

    return ret;
}

/* eof */
