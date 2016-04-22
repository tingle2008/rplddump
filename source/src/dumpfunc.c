//#define DEBUG
//#define PGSQL
#define CMP_IN 

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

#define CHR_LF 	  0x0a
#define CHR_EOL   0x0d
#define CHR_ESC   0x1b
#define CHR_DEL   0x7f
#define CHR_C_H   0x08
#define CHR_TAB   '\t'
#define CHR_BELL  0x07

#if 0

#ifdef PGSQL
#include <libpq-fe.h>
//----
#define PG_USER "postgres"
//#define PG_PASS password
#define PG_HOST "localhost"
#define PG_NAME "test"
#define PG_TABLE "log"
//----
#endif

static int  raw_cmd(int fd, size_t size, char *rest);
static int  wait_ps(const char *PS);
static int  is_chng_ps(char *realcmd);
static int  cmd_match(const char *cmd);
static char *find_cmd(const char *rawcmd);
static char *find_host(const char *buf);
static char *find_ps(char *buf);
static char *cmd_rm_ps(char *cmd, const char *ps);
static char *cmd_preparse(char *buf);
static char *inbuf_preparse(char *buf);
static char *outbuf_preparse(char *buf);
static char *str_rm_char(char *buf, char c);

static int  clear_file(const char *name);
static char *cmd_parse(const char *name, char *buf);

static void myfree(void **);
static int  myrm(const char *name);

static int  my_init_readline(char *name);
static void myrl_noredisplay(void) {};  //for readline, don't re-display inputs

int main(int argc, char *argv[])
{
    int fd = 0;
    int ret = 0;
    int size = 0;
    int wlen = 0;
    int ret_main = -1;
    
    char *buf  	= (char*)NULL;
    char *realcmd = (char *)NULL;
    char *rdlinecmd = (char *)NULL;
    char timebf[25];
    char rl_name[] = "instream_tmp.XXXXXX";

    struct timeval stamp;
    struct rpldsk_packet packet;
    enum CMD_STATUS cmd_s = CMD_UNKNOWN;

#ifdef PGSQL
    char *pgbuf = NULL;
    int  pglen;

    int nfields, ntuples;
    PGresult *res;
    PGconn   *conn;
#endif

    /*arg*/
    if (argc != 2) {
        fprintf(stderr, "Usage: %s rpl_logfile\n", argv[0]);
        exit(1);
    }

    /*logfile readable*/
    if ((fd = open(argv[1], O_RDONLY)) < 0) {
        fprintf(stderr, "could no to open %s: %s", argv[1], strerror(errno));
        exit(1);
    }

    if ((my_init_readline(rl_name)) != 0) {
        fprintf(stderr, "readline init fail.\n");
        exit(1);
    }

#ifdef PGSQL
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
        exit(1);
    }
#endif

    /*
     *----------
     * main proc
     *----------
     */
    while ((ret = read(fd, &packet, 
        sizeof(struct rpldsk_packet))) == sizeof(struct rpldsk_packet))
    {
        //dbg("<-packet->\nsize: %x\nevent: %x\nmagic: %x\n", packet.size, packet.event, packet.magic);
        if (packet.magic != MAGIC_SIG) {
            fprintf(stderr, "\n<Packet inconsistency>\n");

            close(fd);
            exit(1);
        }

        size = packet.size;
        if (size <= 0) {
            fprintf(stderr, ("\n" "<Packet inconsistency>"
                            ": bad size" "\n"));
            close(fd);
            exit(1);
        }

        switch (packet.event) {
            case EVT_WRITE:
                dbg("case EVT_WRITE\n");
                if ((buf = malloc(size+1)) == NULL) {
                    fprintf(stderr, "malloc error\n");
                    close(fd);
                    exit(1);
                }

                read(fd, buf, size); 
                buf[size] = '\0';
                outlen += strlen(buf); // size-1 : remove '\0' in packet.data
                if (outlen >= OUT_BFMAX) {
                    fprintf(stderr, "BUG: OUT_BFMAX to small\n");
                    exit(1);
                }

                strncat(outbuf, buf, size);
                outbuf[outlen-1] = '\0';
                free(buf);
                buf = (char *)NULL;
                //dbg("\n+\n%s\n=\n", outbuf);

                if (Host == NULL) {
                    Host = find_host(outbuf);

                    //dbg("clear outbuf: find_host\n");
                    outlen = 1;
                    outbuf[0] = '\0';
                    break;
                }

                switch (s_cmd) {
                    case CMD_UNKNOWN:
                    case CMD_NEXT:
                    case CMD_BEGIN:
                        /*buffer outputs*/
                        //dbg("EVT_W: buf\n");
                        break;

                    /*
                     *CMD_END: input ok 
                     *    grep rdlinecmd in outbuf(end with '\r'), and complete realcmd 
                     */
                    case CMD_END:
                        dbg("EVT_W: CMD_END(PS:%s)\n", PS);
                        if(PS != NULL) { //ps : 'xxxx' \r PS \r 'realcmd'
                            cmd_rm_ps(outbuf, PS);
                            str_rm_char(outbuf, CHR_LF);
                            str_rm_char(outbuf, CHR_BELL);
                            outlen = strlen(outbuf);
                            outbuf[outlen++] = '\0';

                            cmd_preparse(outbuf);
                            //outbuf_preparse(outbuf);

                            outlen = strlen(outbuf)+2;
                            //add CHR_EOL
                            if (outlen >= OUT_BFMAX) {
                                fprintf(stderr, "BUG: OUT_BFMAX too small!\n");
                                exit(1);
                            }
                            outbuf[outlen-2] = CHR_EOL;
                            outbuf[outlen-1] = '\0';

                            
                            realcmd = cmd_parse(rl_name, outbuf);
                            dbg("\nEVT_W cmd_pase done\noutbuf:(%s)\nrealcmd(%d):\n(%s)\n",
                               outbuf, (int)strlen(realcmd), realcmd);

                            assert(realcmd != NULL);
                            assert(rdlinecmd != NULL);
                            assert(*inbuf != '\0');

                            dbg("\n------out-----");
                            str_rm_char(PS, CHR_BELL);

                               /*/XXX
                               dbg("realcmd:%s\n", realcmd);
                               dbg("rdlinecmd:%s\n", rdlinecmd);
                               dbg("inbuf:%s\n", inbuf);
                               dbg("[%s](%s)%s\n", timebf, PS, inbuf);
                               **/
#ifdef CMP_IN
                            if (strncmp(realcmd, rdlinecmd, strlen(realcmd)) != 0) {
                                str_rm_char(inbuf, CHR_BELL);
                                str_rm_char(inbuf, CHR_EOL);
                                inlen = strlen(inbuf);
                                inbuf[inlen] = '\0';
                                inlen++;
                                //inbuf[inlen-1] = '\0'; //delete last '\r'
#endif
#ifdef PGSQL
                                //dbg("\nPGSQL: with inbuf\n");

                                pglen  = inlen; 		// contain '\0'
                                pglen += 28;   			// length of: "INSERT INTO xx VALUES (xxx, )"
                                pglen += 8*7; 			// 8*length of: "$PGESC$"
                                pglen += strlen(PG_TABLE);
                                pglen += strlen(timebf);  			// timebf;
                                pglen += strlen(realcmd);
                                pglen += strlen(PS);

                                if ((pgbuf = malloc(pglen)) == NULL) {
                                    fprintf(stderr, "malloc failed:@ func(%s),line(%d)\n",
                                        __FUNCTION__, __LINE__);

                                    ret_main = -1;
                                    goto all_exit;
                                }
                                memset(pgbuf, 0, pglen);

                                //dbg("PGSQL: sprintf\n");
                                sprintf(pgbuf, "INSERT INTO %s VALUES ($PGESC$%s$PGESC$, $PGESC$%s$PGESC$, $PGESC$%s$PGESC$, $PGESC$%s$PGESC$)",
                                    PG_TABLE, timebf, PS, realcmd, inbuf);

                                //dbg("\nstrlen(pgbuf):%d, pglen:%d\n", (int)strlen(pgbuf), pglen);
                                //dbg("PGSQL: pgbuf(%s)\n", pgbuf);

                                assert(strlen(pgbuf) < pglen);
                                pgbuf[pglen-1] = '\0';

                                res = PQexec(conn, pgbuf);

                                free(pgbuf);
                                pgbuf = NULL;
                                pglen = 0;
 
                                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                                    fprintf(stderr, "PGSQL insert failed: %s\n",
                                        PQerrorMessage(conn));
                                    PQclear(res);
                                    PQfinish(conn);
                                    exit(1);
                                }
                                PQclear(res);
#else
                                fprintf(stdout, "[%s]%s%s(%s)\n", timebf, PS, realcmd, inbuf); //XXX
                                fflush(stdout);
#endif

#ifdef CMP_IN

                            } else {
                                //cmd ok
                                str_rm_char(realcmd, CHR_BELL);

                                /*
                                inlen = strlen(inbuf);
                                inbuf[inlen] = '\0';
                                inlen++;
                                */
                                //inbuf[inlen-1] = '\0'; //delete '\r'
#ifdef PGSQL
                                //dbg("PGSQL: no inbuf\n");

                                pglen  = 28;   			// length of: "INSERT INTO xx VALUES (xxx)'\0'"
                                pglen += 6*7; 			//6 *length of: "$PGESC$"
                                pglen += strlen(PG_TABLE);
                                pglen += strlen(timebf);  			// timebf;
                                pglen += strlen(realcmd);
                                pglen += strlen(PS);

                                if ((pgbuf = malloc(pglen)) == NULL) {
                                    fprintf(stderr, "malloc failed:@ func(%s),line(%d)\n",
                                        __FUNCTION__, __LINE__);

                                    ret_main = -1;
                                    goto all_exit;
                                }

                                sprintf(pgbuf, "INSERT INTO %s VALUES ($PGESC$%s$PGESC$, $PGESC$%s$PGESC$, $PGESC$%s$PGESC$)",
                                    PG_TABLE, timebf, PS, realcmd);

                                //dbg("\nstrlen(pgbuf):%d, pglen:%d\n", strlen(pgbuf), pglen);

                                assert(strlen(pgbuf) < pglen);
                                pgbuf[pglen-1] = '\0';

                                res = PQexec(conn, pgbuf);

                                free(pgbuf);
                                pgbuf = NULL;
                                pglen = 0;

                                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                                    fprintf(stderr, "PGSQL insert failed: %s\n",
                                        PQerrorMessage(conn));
                                    PQfinish(conn);
                                    exit(1);
                                }
                                PQclear(res);
#else

                                fprintf(stdout, "[%s]%s%s\n", timebf, PS, realcmd); //XXX
                                fflush(stdout);
#endif //PGSQL
                            }
                            dbg("------end out-----\n");
#endif //CMP_IN
        
                            timebf[0] = '\0';

                            if (realcmd && *realcmd) {
                                //dbg("add_history: %s\n", realcmd);
                                add_history(realcmd);
                            }

                            //free: inbuf, rdlinecmd, rdlinecmd, CMD.
                            //realcmd will be used in CMD_WAITPS and be freed after...
                            inbuf[0] = '\0';
                            inlen = 1;

                            outbuf[0] = '\0';
                            outlen = 1;

#ifdef CMP_IN
                            free(rdlinecmd);
                            rdlinecmd = NULL;
#endif

                            //dbg("clear outbuf: realcmd\n");
                            s_cmd = CMD_WAITPS; 
                        }
                        break;

                    //cmd executing, waiting for cmd exit.
                    case CMD_WAITPS:
                        dbg("\nCMD_WAITPS(PS:%s)\n(%s)\n", PS, outbuf);
                        //dbg("\n+\n%s\n-\n", outbuf);
                        assert(PS != NULL);
                        assert(realcmd != NULL);
                        if (outbuf[0] != '\0') {
                            if (is_chng_ps(realcmd) == 0) {
                                //ps will be changed
                                char *tmpps = NULL;
                                if ((tmpps = find_ps(outbuf)) != NULL) {
                                    //dbg("\nupdate PS:(%s)->(%s)\n", PS, tmpps);
                                    if (PS != NULL) {
                                        free(PS);
                                        PS = tmpps;
                                        tmpps = NULL; 
                                       //dbg("PS updated.(PS:%s)\n", PS);
                                    }
                                    outlen = 1;
                                    outbuf[0] = '\0';
    
                                    //dbg("free realcmd ...\n");
                                    free(realcmd);
                                    realcmd = (char *)NULL;

                                    s_cmd = CMD_NEXT;
                                    dbg("done CMD_WAITPS find\n");
                                    break;
                                }
                                if (strchr(outbuf, CHR_BELL) == NULL) {
                                    outbuf[0] = '\0';
                                    outlen = 1;
                                }
                            } else {
                                //ps will not be changed

                                //dbg("\nwait_ps\n(outbuf:%s)\n(PS:%s)\nskip...\n", outbuf, PS);
                                //TODO clear ^G here
                                if (wait_ps(PS) == 0) {
                                    //dbg("\ndone wait_ps(%s)(PS:%s)\n", outbuf, PS);
                                    //dbg("free realcmd ...\n");
                                    free(realcmd);
                                    realcmd = (char *)NULL;

                                    outlen = 1;
                                    outbuf[0] = '\0';

                                    s_cmd = CMD_NEXT;
                                    dbg("done CMD_WAITPS wait\n");
                                    break;
                                }
                                outlen = 1;
                                outbuf[0] = '\0';
                            } //is_chng_ps
                        } //buf[0] != 0
                        //dbg("end CMD_WAITPS\n");
                        break;

                    default:
                        //dbg("EVT_W: default\n");
                        break;
                }

                break;

            case EVT_READ:
                dbg("case EVT_RD: start\n");
                if (PS == NULL) {
                    PS = find_ps(outbuf);
                    outlen = 1;
                    outbuf[0] = '\0';
                }

                //find raw input and parse it with readline()
                if ((s_cmd == CMD_WAITPS) ||
                    (s_cmd == CMD_END))
                {
                    //dbg("\nEVT_RD: skip\n");
                    inlen = 1;
                    inbuf[0] = '\0';
                    lseek(fd, size, SEEK_CUR);
                    break;
                }

                s_cmd = raw_cmd(fd, size, NULL);
                 
                if (s_cmd == CMD_END) {
                    dbg("EVT_RD: CMD_END\n");

                    //dbg("inbuf:%s\n", inbuf);
                    str_rm_char(inbuf, CHR_BELL);

#ifdef CMP_IN
                    char *tmpbuf = NULL;
                    if ((tmpbuf = malloc(inlen)) == NULL) {
                        fprintf(stderr, "malloc error(line: %d, func: %s)",
                            __LINE__, __FUNCTION__);
                        goto all_exit;
                    }
                    
                    memset(tmpbuf, 0, inlen);
                    strncpy(tmpbuf, inbuf, inlen-1);
                    tmpbuf[inlen-1] = '\0';

                    inbuf_preparse(tmpbuf);
                    cmd_preparse(tmpbuf);

                    inlen = strlen(tmpbuf) + 1;
                    tmpbuf[inlen-2] = CHR_EOL;
                    tmpbuf[inlen-1] = '\0';


                    rdlinecmd = cmd_parse(rl_name, tmpbuf);
                    dbg("\ncmd_parse:\n inbuf:(%s)\n rdlinecmd=(%s)\n", tmpbuf, rdlinecmd);
 
                    rdlinecmd[strlen(rdlinecmd)] = '\0';

                    free(tmpbuf);
                    tmpbuf = NULL;
#endif

                    //free rdlinecmd, inbuf at EVT_WRITE side
                    stamp = packet.time;
                    strncpy(timebf, ctime(&(stamp.tv_sec)), 24);
                    timebf[24] = '\0';
                    dbg("EVT_RD: ... done.\n");
                } else if (s_cmd == CMD_BEGIN) {
                    //dbg("EVT_RD: CMD_BEGIN done.\n");
                    break;
                } else if (s_cmd == CMD_NEXT) {
                    inlen = 1;
                    inbuf[0] = '\0';
                    //dbg("EVT_RD: CMD_NEXT done.\n");
                    break;
                } else {
                    //fail and exit();
                    fprintf(stderr, "find raw_cmd error\n");
                    exit(1);
                }

                break;

            case EVT_ID_USER:
                if ((User = malloc(size)) == NULL) {
                    fprintf(stderr, "malloc(User) error.\n");
                    close(fd);
                    exit(1);
                }
                read(fd, User, size); 
                //fprintf(stdout, "User: %s\n", User);
                break;

            case EVT_ID_TIME:
                if ((Time = malloc(size)) == NULL) {
                    fprintf(stderr, "malloc(User) error.\n");
                    close(fd);
                    exit(1);
                } 
                read(fd, Time, size);
                //fprintf(stdout, "Time: %s\n", Time);
                break;
            case EVT_LCLOSE:
                fprintf(stderr, "EVT_LCLOSE\n");
                fflush(stdout);
                inbuf[0]  = '\0';
                outbuf[0] = '\0';
                goto ok_exit;

            default:
                //dbg("EVT: %x, lseek\n", packet.event);
                lseek(fd, size, SEEK_CUR);
                break;
        }
 
    }

ok_exit:
    ret_main = 0;

all_exit:

#ifdef PGSQL
    PQfinish(conn);
#endif

    myrm(rl_name);
    FILE *tmpfp;
    tmpfp = rl_outstream;
    rl_outstream = NULL;
    fclose(tmpfp);

    myfree((void *)&realcmd);
    myfree((void *)&User);
    myfree((void *)&Time);
    myfree((void *)&Host);
    myfree((void *)&PS);

    if (fd != 0)
        close(fd);

    assert(buf == NULL);
    assert(realcmd == NULL);
    assert(rdlinecmd == NULL);
    assert(User == NULL);
    assert(Time == NULL);
    assert(Host == NULL);
    assert(PS == NULL);
    
    exit(ret_main);
}


/*---------
 * readline
 *---------
 */
static int my_init_readline(char *name)
{
    int  i = 0;
    int  fd = 0;
    int  tmplen = 0;
    char *buf   = NULL;
    FILE *tmpfp = (FILE *)NULL;

    char nametmp[] = ".inputrc.XXXXXX";
    char tmpcmd[] = "rm -rf ";
    char *rc[] = {
            "#$include /etc/inputrc\n",
            "set editing-mode emacs\n",
            "set bell-style none\n",
            "set input-meta on\n",
            "set convert-meta on\n",
            "set output-meta on\n",
            "TAB: complete\n ",
            "Meta-Rubout: backward-kill-word\n",
            "\"\\C-a\": beginning-of-line\n",
            "\"\\C-e\": end-of-line\n",
            "\"\\C-f\": forward-char\n",
            "\"\\C-b\": backward-char\n",
            "\"\\C-p\": previous-history\n",
            "\"\\C-n\": next-history  \n",
            "\"\\C-k\": kill-line  \n",
            "\"\\C-u\": unix-line-discard \n",
            "\"\\C-d\": delete-char  \n",
            "\"\\C-h\": backward-delete-char  \n",
//            "\"  \":   \n",
            "\"\x7F\": backward-delete-char  \n",
            NULL
        };


    /********
     inputrc
     ********/
    fd = mkstemp(nametmp);
    //dbg("tmpfile:%s\n", nametmp);
    if (fd == -1) {
        fprintf(stderr, "fopen tmpfile error.");
        return -1;
    }

    for(i=0; rc[i] != NULL; i++) {
        tmplen = strlen(rc[i]);
        if (write(fd, rc[i], tmplen) != tmplen) {
            fprintf(stderr, "WARN: write inputrc fail(line: %d, func: %s).\n",
                __LINE__, __FUNCTION__);
        }
    }
    close(fd);
    fd = 0;

    rl_read_init_file(nametmp); 

    //TODO use myrm(nametmp) here!
    myrm(nametmp);

    rl_redisplay_function = myrl_noredisplay;  //remove outputs of readline();
    //rl_bind_key_in_map();//

    /*tmp file for rl_outstream*/
    tmpfp = tmpfile();
    if (!tmpfp) {
        fprintf(stderr, "can't open tmp stream for rl_outstream!\n");
        return -1;
    }
    rl_outstream = tmpfp;

    if ((fd = mkstemp(name)) == -1) {
        fprintf(stderr, "tmpfile err.\n");
        close(fd);
        return -1;
    }
    close(fd);

    return 0;
}

static void myfree(void **p)
{
    if (*p != NULL) {
        free(*p);
    }
    *p = NULL;

    return;
}

static int myrm(const char *name)
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

static char *find_host(const char *buf)
{
    char *host = (char *)NULL;
    char *p_idx = (char *)NULL;
    int prelen = strlen(HOST_PREFIX);

    //hostname: started by HOST_PREFIX
    if (((p_idx = strstr(buf, HOST_PREFIX)) != NULL) &&
        p_idx[prelen])
    {
        int len = strlen(p_idx+prelen);
        if ((host = (char *)malloc(len + 1)) == NULL) {
            fprintf(stderr, "malloc error in find_host.\n");
            return NULL;
        }
        strncpy(host, p_idx+prelen, len);
        host[len] = '\0';

        //hostname: end by CHR_LF(\r)
        if ((p_idx = strchr(host, CHR_LF)) != NULL) {
            p_idx[0] = '\0';
        }
        //dbg("hostname found:%s\n", host);
    }

    return host;
}

static int raw_cmd(int fd, size_t size, char *rest)
{
    int newlen;
    int ret;
    char *buf    = NULL;
    char *endp   = NULL;
    char *beginp = NULL;

    if (rest == NULL) {
        if ((buf = (char *) malloc(size+1)) == NULL) {
            fprintf(stderr, "malloc error in raw_cmd.\n");
            return CMD_NEXT;
        }
        if (read(fd, buf, size) != size) {
            fprintf(stderr, "\ndata read error\n");
            free(buf);
            buf = 0;
            return CMD_NEXT;
        }
        buf[size] = '\0';
    } else
        buf = rest;

    //dbg("[packet_content]%s\n", buf);
    //dbg("         inbuf]%s\n", inbuf);

    //catch '\r': passwd inputs, delete
    if ((endp = strrchr(buf, CHR_LF)) != NULL) {
        //dbg("endp: %s\n(buf-endp:%s)\n", endp, buf);
        if (endp[1] != '\0') {
            rest = &endp[1];
        }
        inbuf[0] = '\0';
        inlen = 1;
        return CMD_BEGIN; 
    }

    /*
     * else, copy packet.data -> inbuf, and process special ^[[x sequence.
     */
    assert(buf != NULL);
    newlen = strlen(buf);
    if ((newlen + inlen) >= IN_BFMAX) {
        fprintf(stderr, "\nBUG: IN_BFMAX is too small!\n");
        return CMD_NEXT;
    }
    strncat(inbuf, buf, newlen);
    inlen += newlen;
    inbuf[inlen-1] = '\0';
    free(buf);
    buf = (char *)NULL;

    // find first CHR_EOL that ends an input
    if ((endp = strchr(inbuf, CHR_EOL)) != NULL) {
        if (endp[1] != '\0') {
            newlen = strlen(endp+1);
            if ((rest = (char *)malloc(newlen + 1)) != NULL) {
                fprintf(stderr, "malloc error in raw_cmd.\n");
                return CMD_NEXT;
            }
            strncpy(rest, endp+1, newlen);
            rest[newlen] = '\0';
            endp[1] = '\0'; //inbuf
        }
       
        //reserve endp[0](CHR_EOL) for readline 
        //endp[0] = '\0'; //inbuf

        //inbuf[inlen-2]:CHR_EOL, inbuf[inlen-1]:'\0';
        inlen = strlen(inbuf);
        inbuf[++inlen] = '\0';

        //////////
        //TODO sub undefine-seq -> recognized-seq and pass to readline
        /*
         * get whole line, pre-process undefined esc-seq...
         */
        // ^[[K
        buf = malloc(4);
        sprintf(buf, "%c[K", CHR_ESC);
        buf[3] = '\0';
        while (((endp = strstr(inbuf, buf)) != NULL) && endp[3]) {
            newlen = strlen(endp+3);
            inbuf[0] = '\0';
            strncpy(inbuf, endp+3, newlen);
            inlen = newlen+1;
            inbuf[inlen-1] = '\0';
            endp = (char *)NULL;
    
            //dbg("KEY_ESC_^[[K: %s\n", buf);
        }
        free(buf);
        buf = (char *)NULL;
    
        // for DEL-key: ^[[3~
        buf = malloc(5);
        sprintf(buf, "%c[3~", CHR_ESC);
        buf[4] = '\0';
        while ((endp = strstr(inbuf, buf)) != NULL) {
            endp[0] = CHR_ESC;
            endp[1] = '[';
            endp[2] = 'C';
            endp[3] = CHR_DEL;
        }
        free(buf);
        buf = (char *)NULL;

        /*
         * return and let readline parse it
         */
        ////////////
        return CMD_END; 
    }

    return CMD_BEGIN; 
}

/*
 * @ 0: ps found. for cmd which doesn't change PS
 */
static int wait_ps(const char *ps) {
    if (strstr(outbuf, ps) != NULL) {
        return 0;
    } else {
        return 1;
    }
}

/*
 * find PS. for cmd which will change PS
 */
static char *find_ps(char *buf)
{
    char *pcur = (char *)NULL;
    char *ptmp = (char *)NULL;
    char delim[2] = {0};
    int  len = 0;

    assert(buf != NULL);

    if (buf[strlen(buf)-1] == CHR_BELL) {
        return NULL;
    }

    if ((buf[0] == CHR_BELL) && (buf[1] != '\0')) {
        len = strlen(buf+1);
        if ((pcur = malloc(len+1)) == NULL) {
            fprintf(stderr, "WARNING: malloc error.\n");
            return NULL;
        }
        strncpy(pcur, (buf+1), len);
        pcur[len] = '\0';
        return pcur;
    }
    if (buf[0] != '\0') {
        delim[0] = CHR_BELL;
        delim[1] = '\0';
        if (strtok(buf, delim) != NULL) {
            while ((ptmp = strtok(NULL, delim)) != NULL) {
                pcur = ptmp;
            }

            if (pcur != NULL) {
                ptmp = pcur;
                len = strlen(pcur);
                if ((pcur = malloc(len+1)) == NULL) {
                    fprintf(stderr, "malloc fail: %s", strerror(errno));
                    exit(1);
                }
                strncpy(pcur, ptmp, len);
                pcur[len] = '\0';
                ptmp = (char *)NULL; //ptmp -> buf, no need to free it.
            }
        }
    }
 
    return pcur;
}

/*
 * complet raw cmd
 */
/*
static int complet_cmd(char *raw) {
    //TODO
}
 */

/*
 * let readline parse *buf*
 * @ return parsed cmd, caller must free it
 */
static char *cmd_parse(const char *name, char *buf)
{
    int len = 0;
    int wlen = 0;
    char *rdcmd = NULL;
    FILE *fp = NULL;

    str_rm_char(buf, CHR_BELL);

    len = strlen(buf);
    //dbg("buf[%d]: 0x%2x, %c;%s\n", len, buf[len-1], buf[len-1], buf);

    //------------ write to instream ------------//
    if ((fp = fopen(name, "w")) == NULL) {
        fprintf(stderr, "fopen in_stream fail.\n");
        return NULL;
    }

    rewind(fp);
    assert(buf[len-1] == CHR_EOL);

    if (fwrite(buf, sizeof(char), len, fp) != (len)) {
        fprintf(stderr, "fwrite error: %s\n", buf);

        fclose(fp);
        return NULL;
    }
    fflush(fp);
    fclose(fp);
    //------------ write ok------------//

    if ((fp = fopen(name, "r")) == NULL) {
        fprintf(stderr, "fopen in_stream fail.\n");
        return NULL;
    }
    rl_instream = fp;
    fflush(rl_instream);

    rewind(fp);

    //XXX
    /*
    rdcmd = malloc(len+1);
    memset(rdcmd, 0, len+1);

    fgets(rdcmd, len+1, fp);
    dbg("fread: %s\n", rdcmd);
    free(rdcmd);
    rewind(fp);
    */
    //XXX
    
    assert(fp != NULL);
    assert(rl_instream != NULL);
    assert(buf != NULL);
    assert(buf[0] != '\0');

    dbg("-cmd_parse:\n(%s)\n", buf);
    if ((rdcmd = readline("")) == NULL) {
        fprintf(stderr, "FATAL: readline error\n");
        return NULL;
    }

    rl_instream = NULL;
    fclose(fp);
    myrm(name);

    dbg("=cmd_parse done:\n(%s)\n(%s)\n", buf, rdcmd);
    return rdcmd;
}

/*
 * clear instream
 */
static int clear_file(const char *name)
{
    return (truncate(name, 0));
}

/*
 * @ 0: cmd will change PS, 0-> find_ps, 1->wait_ps
 */
static int is_chng_ps(char *realcmd)
{
    char *cmd = NULL;

    assert(realcmd != NULL);

    if ((cmd = strtok(realcmd, "\t\n ")) != NULL) {
        if (strncmp("sudo", cmd, 4) == 0) {
            cmd = strtok(NULL, "\t\n");    //discard "sudo"
        }

        return cmd_match(cmd);
    }

    return -1;
}

/*
 * check whether (cmd) matches one of commands that change PS
 * @ 0 : match, will change PS;   -1: doesn't change PS
 */
static int cmd_match(const char *cmd)
{
    char *cmdlist[] = {
        "cd",
        "su",
        "source",
        "ssh",
         NULL
    };

    int i;
    int len = 0;
    
    if (cmd && cmd[0]) {
        len = strlen(cmd);
        for (i=0; cmdlist[i] != NULL; i++) {
            if (strncmp(cmdlist[i], cmd, len) == 0) {
                return 0;
            }
        }
    }

    return -1;
}

/*
 * get string follows PS
 */
static char *cmd_rm_ps(char *cmd, const char *ps)
{
    if (ps && *ps && cmd && *cmd) {
        int len = strlen(ps);
        char *plast = cmd;
        char *pcur = NULL;

        //dbg("remove_ps:%s(%s)\n", cmd, ps);
        while ((pcur=strstr(plast, ps)) != NULL) {
            plast = pcur+len; // plast <- &pcur[len-1]+1
            //dbg("       ->:%s\n", plast);
            pcur = NULL;
        }

        if (plast != cmd) {
            int newlen = strlen(plast);
            cmd[0] = '\0';
            strncat(cmd, plast, newlen);
            cmd[newlen] = '\0'; //plast points to substring of cmd, so (cmd+newlen) is ok
        }
        //dbg("endrm_ps:%s\n", cmd);
    }
    return cmd;
}


/*
 * remove char 'c' in (char *)buf
 */
char *str_rm_char(char *buf, char c)
{
    char *p = buf;
    int step = 0;

    dbg("\n-str_rm(0x%02x):\n(%s)\n", c, buf);
    //while (p && *p && (p+step) && *(p+step)) {
    while ((p+step) && *(p+step)) {
        while (p[step] == c) {
            step++;
        }

        if (step != 0) {
            *p = p[step];
        }
        p++;
    }
    *p = '\0';

    dbg("=str_rm(0x%02x):\n(%s)\n", c, buf);
    
    return buf;
    //dbg("\n-str_rm(%c):\n(%s)\n", c, buf);
    /*
    while ((p = strchr(buf, c)) != NULL) {
        //dbg("   ->:%s\n", p);
        *p = '\0';
        if (p[1] != '\0') {
            tmplen = strlen(p+1);
            //strncpy(p, p+1, tmplen);
            strncat(p, p+1, tmplen);
            p[tmplen] = '\0'; //(*(p+1)[(tmplen-1)-1];
            //dbg("   =>:%s\n", p);
        }
    }
    */
    //dbg("\n=end_rm:\n(%s)\n\n", buf);
}

/*
 * substitute asc-control string readline can't parse to equiv asc-ctrl-string
 */
static char *outbuf_preparse(char *buf)
{
    // ^[[xxP, ^[[xx@, ^[[3~
    //TODO
    return buf;
}

/*
 * ^H^[[K -> ^H
 */
//static char *outbuf_preparse(char *buf)
static char *cmd_preparse(char *buf)
{
    char delim[5] = {0};
    char *q = NULL;
    char *p = NULL;
    //char *retbuf = NULL;
    int dlen = 0;
    int retlen = 0;

    //delim[0] = CHR_DEL;
    delim[0] = CHR_C_H;
    delim[1] = CHR_ESC;
    delim[2] = '[';
    delim[3] = 'K';
    delim[4] = '\0';

    assert(buf != NULL);

    dbg("\n-cmd_preparse:\n(%s)\n", buf);

    if ((p = strstr(buf, delim)) == NULL) {
        dbg("=cmd_preparse do nothing\n");
        return buf;
    }

    dlen = strlen(delim);
    //p[0-3] -> ^H'\0'xx
    p[0] = CHR_DEL;
    p[1] = '\0';
    retlen = strlen(buf)+1;

    q = p + dlen;

    while (q && *q) {
        if ((p = strstr(q, delim)) != NULL) {
            //p[0-3] -> ^H'\0'xx
            p[0] = CHR_DEL;
            p[1] = '\0';
        }

        while (q && *q) {
            buf[retlen-1] = *q;
            retlen++;
            q++;
        }
        
        buf[retlen-1] = '\0';

        if (p != NULL)
            q = p + dlen;
    }

    dbg("=cmd_preparse(%d):\n(%s)\n", (int)strlen(buf), buf);

    return buf;
    
/*
    retlen = strlen(buf);
    if ((retbuf = malloc(retlen+1)) == NULL) {
        //TODO WARNING
        return buf;
    }
    memset(retbuf, 0, retlen+1);
 
    dbg("-outbuf_preparse:\n(%s)\n", buf);

    p = strstr(buf, delim);

    if (p == NULL) {
        
        //TODO
        //WARNING
    }
    if (p != buf) {
        p += dlen;
    }

    retlen = strlen(p);
    strncpy(retbuf, p, retlen);
    retbuf[retlen++] = '\0';

    while ((p = strstr(NULL, delim)) != NULL) {
        int plen = 0;
        p += dlen;
        plen += strlen(p);

        retbuf[retlen-1] = CHR_DEL;
        retbuf[retlen++] = '\0';

        retlen += plen;
        strncat((retbuf+retlen-1), p, plen);

        retbuf[retlen-1] = '\0';
    }

    dbg(" strtok->(%d):\n(%s)\n", retlen, retbuf);
    buf[0] = '\0';
    strncat(buf, retbuf, retlen-1);
    buf[retlen-1] = '\0';

    free(retbuf);

*/
}

/*
 * sub multi-TAB -> one TAB, as multi-TAB will make readline() call blocks and function will not ret
 * @ 
 */
static char *inbuf_preparse(char *buf)
{
    char *p = buf;
    int  step = 0;
    int  appear  = 0;

    dbg("\n-inbuf_preparse:\n(%s)\n", buf);

    //while (p && *p && (p+step) && *(p+step)) {
    while (p && *p && (*p != CHR_TAB)) {
        p++;
    }

    if (*p == '\0') {
        return buf;
        dbg("=inbuf_preparse: do nothing\n\n");
    }

    appear = 1;
    step = 0;
    p++;
    while ((p+step) && *(p+step)) {
        if (p[step] == CHR_TAB) {
            if (appear == 0) {
                *p = CHR_TAB;
                p++;

                appear = 1;
            } else {
                step++;
            }
        } else {
            appear = 0;
            *p = p[step];
            p++;
        }
    }

    *p = '\0';

    dbg("=inbuf_preparse:\n(%s)\n", buf);

    return buf;
}

#endif

/* eof */
