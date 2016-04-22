#ifndef _LOGOFFSET_H_
#define _LOGOFFSET_H_

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libpq-fe.h>

extern time_t get_cur_mtime(const char *fname);
extern time_t get_last_mtime(PGconn *conn, const char *fname);
extern char *set_last_mtime(PGconn *conn, const char *fname, time_t *ltime);
extern long get_offset(PGconn *conn, const char *fname);
extern char *set_offset(PGconn *conn, const char *fname, long foff);
extern void logpg_finish(PGconn *);
extern PGconn *logpg_conn(void);
//extern PGconn *dbconn(void);

#endif
/* eof */
