#include "logoffset.h"
#include "dumpfunc.h"

/*
#define PG_USER "postgres"                                                                                                    
//#define PG_PASS password
#define PG_HOST "localhost"
#define PG_NAME "test"
#define PG_TABLE "log"
*/


//----
#define OFF_PG_HOST "localhost"
#define OFF_PG_NAME "test"
#define OFF_PG_USER "pguser"
#define OFF_PG_PASS "'123'"
#define OFF_PG_TABLE "pg_offset"
#define TB_NAME  "filename"
#define TB_OFF   "fileoff"
#define TB_MTIME "filemtime"
#define SIZE0    100
#define SIZELONG 22
#define SIZETIME 22
    //"SELECT "TB_OFF" FROM "OFF_PG_TABLE" WHERE "TB_NAME" == %s", fname);
//----


time_t get_cur_mtime(const char *fname)
{
    struct stat *buf;
    time_t ret;

    if ((buf = malloc(sizeof(struct stat))) == NULL) {
        fprintf(stderr, "malloc failed.\n");
        return (time_t)(-1);
    }
    memset(buf, 0, sizeof(struct stat));
    stat(fname, buf);
    if (S_ISREG(buf->st_mode)) {
        ret = buf->st_mtime;
    } else {
        ret = -1;
    }
    free(buf);
    buf = NULL;

    return (time_t)(ret);
}

/*
 * @ -1: error;  0: new log not stored in pg; >0 : select ok
 */
time_t get_last_mtime(PGconn *conn, const char *fname)
{
    PGresult *res;
    int tmp_len;
    int nfields, ntuples;
    long tmp;
    time_t ret;
    const char *paramValues[1];

    paramValues[0] = fname;
    res = PQexecParams(conn,
        "SELECT "TB_MTIME" FROM "OFF_PG_TABLE" WHERE "TB_NAME" = $1;",
        1,
        NULL,
        paramValues,
        NULL,
        NULL,
        0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "PGSQL select failed: %s\n",
            PQerrorMessage(conn));
        PQclear(res);
        return (time_t)-1;
    }

    ntuples = PQntuples(res);
    nfields = PQnfields(res);

    if ((ntuples == 0) || (nfields == 0)) {
        ret = (time_t)0;
    } else {
        if ((tmp_len = PQgetlength(res, 0, 0)) > 0) {
            char *endp;
            tmp = strtol(PQgetvalue(res, 0, 0), &endp, 16);
            if (endp && *endp != '\0') {
                fprintf(stderr, "invalid str for time_t. (line:%d, func: %s)\n",
                    __LINE__, __FUNCTION__);
                ret = (time_t) 0;
            } else {
                ret = (time_t) tmp;
            }
        } else {
            fprintf(stderr, "WARN: PQgetlength is 0 !\n");
            ret = (time_t)0;
        }
    }

    PQclear(res);
    return ret;
}

char *set_last_mtime(PGconn *conn, const char *fname, time_t *ltime)
{
    PGresult *res;
    int nfields, ntuples;
    int i, j;
    char *ret;
    const char *paramValues[2] = {0};

    assert(conn != NULL);
    assert(fname != NULL);
    assert(ltime != NULL);

    paramValues[0] = fname;
    res = PQexecParams(conn,
        "SELECT "TB_NAME" FROM "OFF_PG_TABLE" WHERE "TB_NAME" = $1;",
        1,
        NULL,
        paramValues,
        NULL,
        NULL,
        0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "PGSQL select failed: %s\n",
            PQerrorMessage(conn));
        PQclear(res);
        return NULL;
    }

    ntuples = PQntuples(res);
    PQclear(res);

    if ((ret = malloc(SIZETIME+1)) == NULL) {
        fprintf(stderr, "malloc failed.\n");
        return NULL;
    }
    memset(ret, 0, SIZETIME+1);
    sprintf(ret, "%lx", (long)(*ltime));
    //printf("%s\n", ret);

    if (ntuples > 0) {
        /*fname exists, update mtime*/
        //"UPDATE "OFF_PG_TABLE" SET "TB_OFF" = '%s' WHERE "TB_NAME" = '%s';"
        paramValues[1] = (const char *)ret;
        paramValues[0] = (const char *)fname;
       
        res = PQexecParams(conn,
            "UPDATE "OFF_PG_TABLE" SET "TB_MTIME" = $2 WHERE "TB_NAME" = $1;",
            2,
            NULL,
            paramValues,
            NULL,
            NULL,
            0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "PGSQL update failed: %s\n",
                PQerrorMessage(conn));
            PQclear(res);
            //PQfinish(conn);
            free(ret);
            ret = NULL;
            return NULL;
        }
    } else if (ntuples == 0) {
        //INSERT
        paramValues[1] = ret;
        paramValues[0] = fname;
        res = PQexecParams(conn,
            "INSERT INTO "OFF_PG_TABLE" ("TB_NAME "," TB_MTIME ") VALUES ($1, $2);",
            2,
            NULL,
            paramValues,
            NULL,
            NULL,
            0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "PGSQL insert mtime failed: %s\n",
                PQerrorMessage(conn));
            PQclear(res);
            //PQfinish(conn);
            free(ret);
            ret = NULL;
            return NULL;
        }
    }

    return ret;
}

PGconn *logpg_conn(void)
{
    PGconn *conn = NULL;
    conn = PQconnectdb(
            " host = "OFF_PG_HOST
            " dbname = "OFF_PG_NAME
            " user = "OFF_PG_USER
            " password = "OFF_PG_PASS
        );

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "connect pqsql '"OFF_PG_NAME"' failed: %s\n",
            PQerrorMessage(conn));
        fflush(stderr);
        //PQfinish(conn);
        return NULL;
    }

    return conn;
}

void logpg_finish(PGconn *conn)
{
    PQfinish(conn);
    return;
}

//off_t get_offset(const char *fname)
long get_offset(PGconn *conn, const char *fname)
{
    PGresult *res;
//    PGconn   *conn;
    int nfields, ntuples;
    int i, j;
    long ret;
    const char *paramValues[1];

    //"SELECT "TB_OFF" FROM "OFF_PG_TABLE" WHERE "TB_NAME" = '%s';", fname);
    paramValues[0] = fname;
    res = PQexecParams(conn,
        "SELECT "TB_OFF" FROM "OFF_PG_TABLE" WHERE "TB_NAME" = $1;",
        1,
        NULL,
        paramValues,
        NULL,
        NULL,
        0);

    //if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "PGSQL select failed: %s\n",
            PQerrorMessage(conn));
        fflush(stderr);
        PQclear(res);
        //PQfinish(conn);
        return -1;
    }

    nfields = PQnfields(res);
    ntuples = PQntuples(res);
    //assert(nfields == 1);
    /*
    for (i = 0; i < nfields; i++) {
        for (j = 0; j < ntuples; j++) {
            fprintf(stdout, "%-10s", PQgetvalue(res, i, j));
        }
        fprintf(stdout, "\n");
        fflush(stdout);
    }
    */

    ret = atol(PQgetvalue(res, 0, 0));
    PQclear(res);
    //PQfinish(conn);
    //logpg_finish(&conn);
    return ret;
}

char *set_offset(PGconn *conn, const char *fname, long foff)
{
    PGresult *res;
    //PGconn   *conn;
    int nfields, ntuples;
    int i, j;
    char *ret = NULL;
    const char *paramValues[2];

/*
    conn = PQconnectdb(
            " user = "OFF_PG_USER
            " password = "OFF_PG_PASS
            " dbname = "OFF_PG_NAME
            " host = "OFF_PG_HOST
        );

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "connect pqsql '"OFF_PG_NAME"' failed: %s\n",
            PQerrorMessage(conn));
        fflush(stderr);
        PQfinish(conn);
        return NULL;
    }
*/

    ret = (char *)malloc(SIZELONG+1);
    sprintf(ret, "%ld", foff);
    assert(strlen(ret) < SIZELONG);
    ret[SIZELONG] = '\0';

    //"SELECT "TB_NAME" FROM "OFF_PG_TABLE" WHERE "TB_NAME" = '%s';", fname
    paramValues[0] = fname;
    paramValues[1] = ret;
    res = PQexecParams(conn,
        "SELECT "TB_NAME" FROM "OFF_PG_TABLE" WHERE "TB_NAME" = $1;",
        1,
        NULL,
        paramValues,
        NULL,
        NULL,
        0);

    //if (PQresultStatus(res) != PGRES_COMMAND_OK) {
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "PGSQL select failed: %s\n",
            PQerrorMessage(conn));
        fflush(stderr);
        PQclear(res);
        //PQfinish(conn);
        free(ret);
        ret = NULL;
        return NULL;
    }
    nfields = PQnfields(res);
    PQclear(res);

    if (nfields > 0) {
        /* fname already exists, update its offset */
        res = PQexecParams(conn,
            "UPDATE "OFF_PG_TABLE" SET "TB_OFF" = $2 WHERE "TB_NAME" = $1;",
             2,
             NULL,
             paramValues,
             NULL,
             NULL,
             0);

        //if (PQresultStatus(res) != PGRES_TUPLES_OK ) {
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "PGSQL update failed: %s\n",
                PQerrorMessage(conn));
            fflush(stderr);
            PQclear(res);
            //PQfinish(conn);
            return NULL;
        }
    
    } else {
        /* fname doesn't exist, insert */
        res = PQexecParams(conn,
            "INSERT INTO "OFF_PG_TABLE" VALUES ($1, $2);",
             2,
             NULL,
             paramValues,
             NULL,
             NULL,
             0);
    
        if (PQresultStatus(res) != PGRES_COMMAND_OK ) {
            fprintf(stderr, "PGSQL insert failed: %s\n",
                PQerrorMessage(conn));
            fflush(stderr);
            PQclear(res);
            //PQfinish(conn);
            free(ret);
            ret = NULL;
            return NULL;
        }
    }

    PQclear(res);
    //PQfinish(conn);
    return ret;
}

/*
 * connect to cmdlog-pgsql
 *
PGconn *dbconn(void)
{
    char *pgbuf = NULL;
    int  pglen;

    int nfields, ntuples;
    PGresult *res;
    PGconn   *conn;


    conn = PQconnectdb(
            "user = " PG_USER
            " dbname = " PG_NAME
            " host= " PG_HOST
        );
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "connect pgsql failed: %s\n",
            PQerrorMessage(conn));
        fflush(stderr);
        PQfinish(conn);
        return NULL;
    }

    return conn;                                                                                                              
}
*/

/* eof */
