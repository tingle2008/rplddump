#ifndef __RPLDDUMP_H__
#define __RPLDDUMP_H__

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#include <readline/readline.h>
#include <readline/history.h>

#define CHR_LF 	  0x0a
#define CHR_EOL   0x0d
#define CHR_ESC   0x1b
#define CHR_DEL   0x7f
#define CHR_C_H   0x08
#define CHR_TAB   '\t'
#define CHR_BELL  0x07

#define DEBUG
//#define PGSQL
#define CMP_IN 
#define WALK_LOG

#ifdef PGSQL
    #include <libpq-fe.h>
    #include "logoffset.h"
    //----
    #define PG_USER "postgres"
    //#define PG_PASS password
    #define PG_HOST "localhost"
    #define PG_NAME "test"
    #define PG_TABLE "log"
    //----
#else
    #define PGconn void
#endif

typedef enum CMD_STATUS {
    CMD_UNKNOWN = 0,
    CMD_BEGIN,
    CMD_END,
} status_t;

#ifdef DEBUG
    #define dbg(fmt...) \
        do {            \
            fprintf(stderr, fmt); \
            fflush(stderr); \
            fflush(stdout); \
        } while(0);
#else
    #define dbg(fmt...) 
#endif

#define here \
    do { 		\
        fprintf(stderr, "Here:(line:%d),(func:%s)\n", 	\
            __LINE__, __FUNCTION__); 	\
        fflush(stderr); 		\
    } while(0);

//inbuf: 10K
#define IN_BFMAX 10*1024

//outbuf: 1M
#define OUT_BFMAX 1024*1024

#define HOST_PREFIX "hostname    : "

int myrm(const char *);
void myfree(void **);

#endif
