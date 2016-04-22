#include "rpl_packet.h"
#include "rplddump.h"

status_t s_cmd = CMD_UNKNOWN;

static char *User     = (char *)NULL;
static char *Time     = (char *)NULL;
static char *Host     = (char *)NULL;
static char *PS       = (char *)NULL;

static char inbuf[IN_BFMAX] = {0};
static int  inlen = 1;
static int  last_inlen = 1;

static char outbuf[OUT_BFMAX] = {0};
static int  outlen = 1;
static int  last_outlen = 0;

char rl_name[] = "instream_tmp.XXXXXX";


static int file_parse(int fd,
               PGconn *conn,
               const char *abs_path);

static int update_off_mtime(const char *file, int fd);

static int  logopen(const char *);
static char *find_host(const char *buf);
static int  ps_clean(char **ps);
static char *find_ps(const char *buf);
static int  match_ps(const char *ps);
static int  match_ps2(const char *ps);
static int  clear_file(const char *name);
static char *cmd_parse(char *buf);
static char *cmd_preparse(char *buf);
static char *inbuf_preparse(char *buf);
static char *getcmd(char *buf, char **prdlinecmd, const char *);

static int ps_appear(const char *ps, const char *p);
static void clear_inbuf(void);
static void clear_outbuf(void);
static int is_last_tab(const char *buf);
static int is_cmdend(const char *buf);
static char *last_ttyio(const char *buf, size_t len);
static char *str_rm_char(char *buf, char c);
static int format_time(char **, time_t *);

static int logdump(const char *timebf, const char *ps,
       const char *cmd, const char *file, const char *user);


static int do_add_comp(const char *word);
static int add_completion(char *prefex, char *all_possible);
static int add_comp_multi(const char *prefix, char *all_possible);
static int add_comp_single(char *prefix,
       char *all_possible, char **completed);

static char *split_tab(const char *prefix,
    char **p_pre_word, char **p_tails);

#ifdef PGSQL
    static PGconn *dbconn(void);
#endif

/*
void myfree(void **);
int  myrm(const char *name);
*/

static int  my_init_readline(char *name);
static void my_close_readline(char *name);
static void myrl_noredisplay(void) {};  //for readline, don't re-display inputs

/*--------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    int ret = -1;
    int fd = 0;
    char *abs_path = (char *)NULL;

    PGconn *conn;

    /*arg*/
    if (argc != 2) {
        fprintf(stderr, "Usage: %s rpl_logfile\n", argv[0]);
        exit(1);
    }

    // get absolute path of logfile    
    abs_path = realpath(argv[1], NULL);
    if (abs_path == NULL) {
        fprintf(stderr, "realpath failed: %s\n", strerror(errno));
        exit(1);
    }

#ifdef PGSQL
    //connect log-pgsql database
    if ((conn = dbconn()) == NULL) {
        exit(1);
    }
#endif

    // open logfile, and seek file-offset
    // TODO resume PS, USER, history
    if ((fd = logopen(abs_path)) < 0)
        exit(1);

    // init readline
    if ((my_init_readline(rl_name)) != 0) {
        fprintf(stderr, "readline init fail.\n");
        exit(1);
    }

    if ((ret = file_parse(fd, conn, abs_path)) == 0) {
        update_off_mtime(abs_path, fd);
    }

    //TODO update log-offset in pg_offset
    if (fd != 0)
        close(fd);
   
    my_close_readline(rl_name); 

#ifdef PGSQL
    PQfinish(conn);
#endif

//    myfree((void *)&realcmd);
    myfree((void *)&User);
    myfree((void *)&Time);
    myfree((void *)&Host);
    myfree((void *)&PS);

/*
    assert(buf == NULL);
    assert(realcmd == NULL);
    assert(rdlinecmd == NULL);
*/
    assert(User == NULL);
    assert(Time == NULL);
    assert(Host == NULL);
    assert(PS == NULL);

    exit(ret);
}

static void my_close_readline(char *rl_name)
{
    myrm(rl_name);
    FILE *tmpfp;
    tmpfp = rl_outstream;
    rl_outstream = NULL;
    fclose(tmpfp);

    return;
}


/*
 *----------
 * main proc
 *----------
 */
static int file_parse(int fd, PGconn *conn, const char *abs_path)
{
    int ret = 0;
    int size = 0;
    int wlen = 0;

	char *buf  	= (char*)NULL;
	char *realcmd = (char *)NULL;
    char *rdlinecmd = (char *)NULL;

#define TM_LEN 25
    //char timebf[TM_LEN];
    char *timebf = NULL;

    //struct timeval stamp;
    struct rpldsk_packet packet;
    struct timeval stamp;
    enum CMD_STATUS cmd_s = CMD_UNKNOWN;

    if ((timebf = malloc(TM_LEN)) == NULL) {
        fprintf(stderr, "malloc failed.\n");
        return -1;
    } 
    memset(timebf, 0, TM_LEN);

    while ((ret = read(fd, &packet, 
        sizeof(struct rpldsk_packet))) == sizeof(struct rpldsk_packet))
    {
        //dbg("<-packet->\nsize: %x\nevent: %x\nmagic: %x\n", packet.size, packet.event, packet.magic);
        if (packet.magic != MAGIC_SIG) {
            fprintf(stderr, "\n<Packet inconsistency>\n");
            return -1;
        }

        size = packet.size;
        if (size <= 0) {
            fprintf(stderr, ("\n" "<Packet inconsistency>"
                            ": bad size" "\n"));
            return -1;
        }

        switch (packet.event) {
            case EVT_WRITE:
                dbg("case EVT_WRITE\n");
            
                /* read packet.size and store in outbuf */
                if ((buf = malloc(size+1)) == NULL) {
                    fprintf(stderr, "malloc error\n");
                    close(fd);
                    return -1;
                }
                
                read(fd, buf, size); 
                buf[size] = '\0';

#ifdef WALK_LOG
                dbg("\n[TTY_OUT]\n............\n%s\n............\n\n", buf);
                //break;
#endif

                last_outlen = strlen(buf); // size-1 : remove '\0' in packet.data

                if (s_cmd == CMD_BEGIN) { 
                    outlen += last_outlen;
                } else {
                    outlen = last_outlen+1;
                    outbuf[0] = '\0';
                }

                if (outlen >= OUT_BFMAX) {
                    fprintf(stderr, "BUG: OUT_BFMAX to small\n");
                    exit(1);
                }
               
                strncat(outbuf, buf, size);
                outbuf[outlen-1] = '\0';

                free(buf);
                buf = (char *)NULL;

                break;

            case EVT_READ:
                dbg("case EVT_RD: start\n");
                if (PS == NULL) {
                    if (outbuf[0] == '\0') {
                        fprintf(stderr, "BUG: No PS but outbuf is null.\n");
                        //lseek(fd, size, SEEK_CUR);
                        //break;
                    }
                }

                char *tmp = find_ps(outbuf);
                if (tmp && *tmp) {
                    //update_ps
                    if (PS != NULL) {
                        free(PS);
                        PS = NULL;
                    }
                    PS = tmp;
                    dbg("\nps found\n--\n%s\n--\n", PS);
                    clear_inbuf();

                    stamp = packet.time;
                    s_cmd = CMD_BEGIN;
                    dbg("\nCMD_BEGIN...\n");
                }

                if (s_cmd != CMD_BEGIN) {
                    lseek(fd, size, SEEK_CUR);

                    clear_inbuf();
                    clear_outbuf();
                    break;
                }

                //add_completion if last_inbuf is 'tab'
                buf = last_ttyio(inbuf, last_inlen);
                dbg("\n\n-inbuf-\n%s\n-lastin(%d)-\n%s\n-outbuf-\n%s\n\n", inbuf, last_inlen, buf, outbuf);
                if (is_last_tab(buf) == 0) {
                    str_rm_char(outbuf, CHR_BELL);    
                    add_completion(inbuf, outbuf);
                    dbg("**inbuf-updated:%s\n", inbuf);
                }

                myfree((void *)&buf);
                clear_outbuf();

                //read new tty_in
                if ((buf = malloc(size+1)) == NULL) {
                    fprintf(stderr, "malloc error\n");
                    close(fd);
                    return -1;
                }
                
                read(fd, buf, size); 
                buf[size] = '\0';

#ifdef WALK_LOG
                dbg("\n[TTY_IN]\n............\n%s\n............\n\n", buf);
                //break;
#endif

                last_inlen = strlen(buf); // size-1 : remove '\0' in packet.data

                inlen += last_inlen;
                if (inlen >= OUT_BFMAX) {
                    fprintf(stderr, "BUG: OUT_BFMAX to small\n");
                    exit(1);
                }

                strncat(inbuf, buf, size);
                inbuf[inlen-1] = '\0';

                if (is_cmdend(inbuf) == 0) {
                    dbg("\n...CMD_END.\n");
                    //get rdlinecmd from rd-pkt.data
                    getcmd(inbuf, &rdlinecmd, rl_name);

                    format_time(&timebf, &(stamp.tv_sec));
                    dbg("\n\nrdlinecmd(%s)\n-inbuf-\n%s\n--\n\n", rdlinecmd, inbuf);

                    //output dumped log
                    logdump(timebf, PS, rdlinecmd, abs_path, User);
                    //fprintf(stdout, "[%s]%s%s\n", timebf, PS, rdlinecmd);

                    if (rdlinecmd && *rdlinecmd)
                    {
                        if (!(PS[0] == '>'))
                            add_history(rdlinecmd);
                    }

                    free(rdlinecmd);
                    rdlinecmd = NULL;

                    clear_inbuf();
                    s_cmd = CMD_END;
                }

                free(buf);
                buf = (char *)NULL;


                //get rdlinecmd from rd-pkt.data
                //parse_rd_pkt(fd, &rdlinecmd, &packet, rl_name, &timebf); 
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
                dbg("EVT_LCLOSE\n");
                fflush(stdout);
                clear_inbuf();
                clear_outbuf();
                return 0;

            default:
                dbg("EVT: %x, lseek\n", packet.event);
                lseek(fd, size, SEEK_CUR);
                break;
        }
 
    }
 
    free(timebf);

    return 0;
}


static int logdump(const char *timebf, const char *PS,
                   const char *rdlinecmd, const char *file, const char *user)
{
#define COLOR_OUT

    fprintf(stdout, 
#ifdef COLOR_OUT
            "\n([1;34m%s@%s[0m)\n[[1;33m%s[0m][1;32m%s[0m[1;31m%s[0m\n",
                 user, file, timebf, PS, rdlinecmd);
#else
            "\n(%s@%s)\n[%s]%s%s\n",
                 user, file,
                 timebf, PS, rdlinecmd);
#endif
    return 0;
}

static int is_cmdend(const char *buf)
{
    int len = 0;
    char c0;

    if (buf == NULL)
        return -1;

    len = strlen(buf);
    //'x^M\0'
    if (len < 2)
        return -1;

    c0 = buf[len-1];

    if (c0 == CHR_EOL) {
       return 0;
    }

    return -1;
}

static int is_last_tab(const char *buf)
{
    int len = 0;
    char *p = NULL;

    if (buf == NULL)
        return -1;

    len = strlen(buf);
    if (len < 1) 
        return -1;

    if ((p = strchr(buf, CHR_TAB)) != NULL) {
        return 0;
    }

    return -1;
}

static int add_completion(char *prefix, char *all_possible)
{
    char *p = NULL;
    char *buf = NULL;
    char *endp = NULL;
    #define MULTI_COMP 0
    #define SINGL_COMP 1
    int compl_mode = SINGL_COMP;
    int ret = -1;

    dbg("add_completion\nprefix:(%s)\nall_possible:\n--\n%s\n--\n", prefix, all_possible)

    //pre-process 'all_possible'
    if ((all_possible == NULL) ||
            ((strlen(all_possible) == 1) && all_possible[0] == CHR_BELL))
    {
        return -1;
    }
  
    //delete ps from 'all_possible' 
    while (((endp = strrchr(all_possible, CHR_LF)) != NULL) &&
        (endp[1] != '\0')) 
    {
        if (ps_appear(PS, endp+1) == 0) {
            endp[0] = '\0';
            compl_mode = MULTI_COMP;
            break;
        }

        endp[0] = ' ';
        buf = endp+1;
        endp = NULL;
    }

    char *completed = NULL;
    size_t len_compl = 0;

    switch(compl_mode) {
        case MULTI_COMP:
            ret = add_comp_multi(prefix, all_possible);
            str_rm_char(inbuf, CHR_TAB);
            break;

        case SINGL_COMP:
            ret = add_comp_single(prefix, all_possible, &completed);
here 
            dbg("=>completed: %s\n", completed);
            //update inbuf -- single-match
            if (completed != NULL) {
                clear_inbuf();
                dbg("=>completed: %s\n", completed);
                len_compl = strlen(completed);
                if (len_compl < IN_BFMAX) {
                    strncpy(inbuf, completed, len_compl);
                    inbuf[len_compl] = '\0';
                    inlen = len_compl + 1;
                    last_inlen = 0;
                }
               
                free(completed);
                completed = NULL; 
            }
            break;

        default:
            return -1;
    }

    return ret;
}

char *rpl_strdup(const char *word)
{
    size_t len = 0;
    char *ret = NULL;

    if (word == NULL) {
        return NULL;
    }

    len = strlen(word);
    if ((ret = malloc(len+1)) == NULL) {
        fprintf(stderr, "malloc failed.(func: %s, line: %d)\n",
            __FUNCTION__, (int)__LINE__);
        return NULL;
    }
    strncpy(ret, word, len);
    ret[len] = '\0';

    return ret;
}

static int add_comp_single(char *prefix, char *all_possible, char **completed)
{
    int ret = -1;

    size_t len = 0;
    size_t pre_len = 0;
    size_t comp_len = 0;
    size_t tail_len = 0;

    char *p = NULL;
    char *buf = NULL;
    char *endp = NULL;

    char *pre_word = NULL;
    char *comp_word = NULL;
    char *tails = NULL;

    dbg("%s\nprefix:(%s)\nall_possible:\n--\n%s\n--\n", 
        __FUNCTION__, prefix, all_possible);


    //get last partial-word for tab-completion
    buf = split_tab(prefix, &pre_word,&tails);

    if (pre_word != NULL)
        pre_len = strlen(pre_word);
    else
        pre_len = 0;

    if (tails != NULL)
        tail_len = strlen(tails);
    else
        tail_len = 0;

    //merge <comp_word> + <p>
    //TODO: make sure all_possible contains only one word.
    //p = strtok(all_possible, " \t\n");
    p = strtok(all_possible, "\t\n"); //remain 'space'
    if (p == NULL)
        return -1;

    len = strlen(p);

    dbg("\npremerge:\npre_word(%d)", (int)pre_len);
    if (pre_len != 0)    
        dbg(":(%s)\n", pre_word);
    dbg("p(%d):(%s)\n", (int)len, p);
    if (tail_len != 0)
        dbg("tails(%d):(%s)\n", (int)tail_len, tails);

    if ((buf = malloc(pre_len+len+tail_len+1)) == NULL) {
        fprintf(stderr, "func(%s), line(%d): malloc failed.\n",
            __FUNCTION__, (int)__LINE__);
        return -1;
    }

    if (pre_len != 0)
        snprintf(buf, (pre_len+1), "%s", pre_word);

    snprintf(buf+pre_len, (len+1), "%s", p);

    if (tail_len != 0)
        snprintf(buf+pre_len+len, (tail_len+1), "%s", tails);

    buf[pre_len+tail_len+len] = '\0';
    ret = do_add_comp(buf+pre_len);

    (*completed) = buf;
    
    myfree((void **)&pre_word);
    myfree((void **)&comp_word);
    myfree((void **)&tails);

    return ret;
}


//TODO
static char *split_tab(const char *prefix,
    char **p_pre_word, char **p_tails)
{
    size_t len = 0;
    size_t pre_len = 0;
    char *endp = NULL;
    char *tmp_word = NULL;
    char *pre_word  = NULL;
    char *tails     =  NULL;

    if (prefix != NULL) {
        pre_len = strlen(prefix);
    }

    //prefix -> pre_word
    if ((pre_word = malloc(pre_len+2)) == NULL) { 
        fprintf(stderr, "func(%s), line(%d): malloc failed.\n",
                __FUNCTION__, (int)__LINE__);
        return NULL;
    }
    memset(pre_word, 0, pre_len+1);
    strncpy(pre_word, prefix, pre_len);

    if ((endp = strrchr(pre_word, CHR_TAB)) != NULL) {
        tails = rpl_strdup(endp+1);
        endp[0] = '\0';
    }

    str_rm_char(pre_word, CHR_TAB);
    len = strlen(pre_word);
    pre_word[len] = CHR_EOL;
    pre_word[len+1] = '\0';

    //cmd_parse
    inbuf_preparse(pre_word);
    tmp_word = cmd_parse(pre_word);
    free(pre_word);
    pre_word = tmp_word;

    tmp_word = NULL;
    len = strlen(pre_word);
    pre_word[len] = '\0';

    (*p_pre_word) = pre_word;
    (*p_tails)    = tails;

    pre_word = tails = NULL;
    return (*p_pre_word);
}

static int add_comp_multi(const char *prefix, char *all_possible)
{
    int len = 0;
    int ret = -1;
    char *p = NULL;
    char *buf = NULL;
    char *endp = NULL;

    dbg("%s\nprefix:(%s)\nall_possible:\n--\n%s\n--\n", 
        __FUNCTION__, prefix, all_possible);

    //get one word from all_possible and do_add_comp
    p = strtok(all_possible, " \t\n");
    if (p == NULL)
        return -1;

    while (p) {
        len = strlen(p);
        if ((buf = malloc(len+1)) == NULL) {
            fprintf(stderr, "func(%s), line(%d): malloc failed.\n",
                __FUNCTION__, (int)__LINE__);
            return -1;
        }
        memset(buf, 0, len+1);
    
        dbg("p:(%s)\n", p);
        strncpy(buf, p, len);
        buf[len] = '\0';
    
        ret = do_add_comp(buf);
        
        free(buf);
        buf = NULL;
        p = strtok(NULL, " \t\n");
    }

    return ret;
}

static int ps_appear(const char *ps, const char *p)
{
    char *endp = NULL;
    assert((ps != NULL) && (p != NULL));

    if ((endp = strstr(p, ps)) != NULL)
        return 0;

    return -1;
}

static int do_add_comp(const char *word)
{

    char *endp = NULL;
    if (((endp = strchr(word, ' ')) != NULL) ||
        ((endp = strchr(word, '\t')) != NULL) ||
        ((endp = strchr(word, '\t')) != NULL)
       )
    {
        fprintf(stderr, "\ndo_add_comp<bad-word>:%s\n", word);
        return -1;
    }

    fprintf(stderr, "\ndo_add_comp:%s\n", word);
    return 0;
}

static void clear_inbuf(void)
{
    inbuf[0] = '\0';
    inlen = 1;
    last_inlen = 0;
}

static void clear_outbuf(void)
{
    outbuf[0] = '\0';
    outlen = 1;
    last_outlen = 0;
}
//================
static char *getcmd(char *buf, char **prdlinecmd, const char *rl_name)
{
    char *tmpbuf = NULL;
    int len = 0;

    len = strlen(buf);

    str_rm_char(buf, CHR_BELL);

    if ((tmpbuf = malloc(len+1)) == NULL) {
        fprintf(stderr, "malloc error(line: %d, func: %s)",
            __LINE__, __FUNCTION__);
        return NULL;
    }
    
    memset(tmpbuf, 0, len+1);
    strncpy(tmpbuf, buf, len);
    tmpbuf[len] = '\0';

    inbuf_preparse(tmpbuf);
    cmd_preparse(tmpbuf);

    len = strlen(tmpbuf);
    tmpbuf[len-1] = CHR_EOL;
    tmpbuf[len] = '\0';


    (*prdlinecmd) = cmd_parse(tmpbuf);
    //dbg("\ncmd_parse:\n inbuf:(%s)\n rdlinecmd=(%s)\n", tmpbuf, *prdlinecmd);
 
    (*prdlinecmd)[strlen(*prdlinecmd)] = '\0';

    free(tmpbuf);
    tmpbuf = NULL;

    //free rdlinecmd, inbuf at EVT_WRITE side
    dbg("EVT_RD: ... done.\n");

    return (*prdlinecmd);
}
//================

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

/*
 * find PS. for cmd which will change PS
 */
static char *find_ps(const char *buf)
{
    char *ps = NULL;
    int tlllen = strlen(buf);
    int is_match = -1;

    ps = last_ttyio(outbuf, last_outlen);
    //last_outlen = 0;

    if (ps == NULL) {
        return NULL;
    }

    is_match = match_ps(ps);
    ps_clean(&ps);

    dbg("\n--\nis_match:(%d)\n(%s)\n--\n", is_match, ps);

    if (is_match == 0) {
        return ps;
    } else {
        free(ps);
        return NULL;
    }
}

static int ps_clean(char **ps)
{
    int i = 0;
    int ret = -1;
    size_t ps_len = 0;
    size_t tok_len = 0;
    char *endp = NULL;
    char *p_ps = NULL;
    char *buf = NULL;

    //'^[[m'
    //'^[[00m'
    //'^[[K'
    char *tok_ps[] = {
            "[m",
            "[00m",
            "[K",
            NULL,
        };

    if (*ps == NULL)
        return -1;

    p_ps = *ps;

    //clean xxx^M
    if (((endp = (strrchr(p_ps, CHR_LF))) != NULL) && (endp[1] != '\0')) {
        p_ps = endp+1;
    }

    for (i=0; tok_ps[i] != NULL; i++) {
        if ((tok_len = strlen(tok_ps[i])) != '\0') {
            if (((endp = strstr(p_ps, tok_ps[i])) != NULL)) {
                if ((ps_len = strlen(endp+tok_len)) != 0) {
                    p_ps = endp+tok_len;
                    ret = 0;
                } else {
                    fprintf(stderr, "\n**WARNING: ps is NULL after tok_clean.\nps\n--\n%s\n--\ntok\n--\n%s\n--\n\n",
                        p_ps, tok_ps[i]);
                    return -1;
                }
            }
        }
    }

    if ((buf = rpl_strdup(p_ps)) != NULL) {
        free(*ps);
        *ps = buf;
    }

    return ret;
}

static int match_ps2(const char *ps)
{
    size_t len = 0;
    char c0, c1;
 
    len = strlen(ps);
    if (len < 2)
        return -1;
 
    //case: start with "> "(PS2)
    c0 = ps[0];
    c1 = ps[1];
    if ((c0 == '>') && (c1 == ' ')) {
        dbg("-> match_ps2\n");
        return 0;
    }

    return -1;
}


static int match_ps(const char *ps)
{
    int len = 0;
    char c0, c1;

    if (ps == NULL)
        return -1;

    if (match_ps2(ps) == 0)
        return 0;

    len = strlen(ps);
    if (len < 1) 
        return -1;

    //TODO XXX
#ifdef PS_SINGLE_OK
    if (len == 1)
    {
        c0 = ps[0];
        if (
            (c0 == '$') ||
            (c0 == '#') ||
            (c0 == '%') ||
            (c0 == '>')
           )
        {  
            return 0;
        } else {
            return -1;
        }
    }
#endif

    //case: end with "$ ", "# ", "% ", "> "
    c0 = ps[len-1];
    c1 = ps[len-2];

    if (
#ifdef PS_WITH_NOSPACE
//'xxx$'
        (c0 == '$') || 
        (c0 == '#') ||
        (c0 == '%') ||
        (c0 == '>') ||
#endif
//'xxx$ '
        (((c0 == ' ') && (
                          (c1 == '$') ||
                          (c1 == '#') ||
                          (c1 == '%') ||
                          (c1 == '>')
                         )
        ))
        //  && (strchr(ps, '@'))
        )
    {
        return 0;

    }

    return -1;
}

static char *last_ttyio(const char *buf, size_t len)
{
    int tlllen = 0;
    char *lastio = NULL;

    if (buf == NULL)
        return NULL;

    tlllen = strlen(buf);
    if ((tlllen == 0) || (len == 0)) {
        return NULL;
    }

    if ((lastio = malloc(len+1)) == NULL) {
        fprintf(stderr, "malloc failed. (%s, %d)\n",
            __FUNCTION__, __LINE__);
        return NULL;
    }
    memset(lastio, 0, len+1);

    strncpy(lastio, (buf+tlllen-len), len);
    lastio[len] = '\0';

    return lastio;
}

/*
 * complet raw cmd
 */
/*
static int complet_cmd(char *raw) {
}
 */

/*
 * let readline parse *buf*
 * @ return parsed cmd, caller must free it
 */
//static char *cmd_parse(const char *name, char *buf)
static char *cmd_parse(char *buf)
{
    int len = 0;
    int wlen = 0;
    char *rdcmd = NULL;
    FILE *fp = NULL;

    str_rm_char(buf, CHR_BELL);

    len = strlen(buf);
    //dbg("buf[%d]: 0x%2x, %c;%s\n", len, buf[len-1], buf[len-1], buf);

    //------------ write to instream ------------//
    if ((fp = fopen(rl_name, "w")) == NULL) {
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

    if ((fp = fopen(rl_name, "r")) == NULL) {
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

    //dbg("-cmd_parse:\n(%s)\n", buf);
    if ((rdcmd = readline("")) == NULL) {
        fprintf(stderr, "FATAL: readline error\n");
        return NULL;
    }

    rl_instream = NULL;
    fclose(fp);
    myrm(rl_name);

    //dbg("=cmd_parse done:\n(%s)\n(%s)\n", buf, rdcmd);
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
 * remove char 'c' in (char *)buf
 */
char *str_rm_char(char *buf, char c)
{
    char *p = buf;
    int step = 0;

    //dbg("\n-str_rm(0x%02x):\n(%s)\n", c, buf);
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

    //dbg("=str_rm(0x%02x):\n(%s)\n", c, buf);
    
    return buf;
    //dbg("\n=end_rm:\n(%s)\n\n", buf);
}

/*
 * ^H^[[K -> ^H
 */
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

    //dbg("\n-cmd_preparse:\n(%s)\n", buf);

    if ((p = strstr(buf, delim)) == NULL) {
        //dbg("=cmd_preparse do nothing\n");
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

    //dbg("=cmd_preparse(%d):\n(%s)\n", (int)strlen(buf), buf);

    return buf;
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

    //dbg("\n-inbuf_preparse:\n(%s)\n", buf);

    //while (p && *p && (p+step) && *(p+step)) {
    while (p && *p && (*p != CHR_TAB)) {
        p++;
    }

    if (*p == '\0') {
        return buf;
        //dbg("=inbuf_preparse: do nothing\n\n");
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

    //dbg("=inbuf_preparse:\n(%s)\n", buf);

    return buf;
}

static int update_off_mtime(const char *file, int fd)
{
#ifdef PGSQL
    PGconn *conn;
    time_t now = -1;
    off_t  off = -1;
    char *ret = NULL;

    if ((conn = logpg_conn()) == NULL)
        return -1;

    time(&now);
    if ((ret = set_last_mtime(conn, file, &now)) == NULL) {
        fprintf(stderr, "set_last_mtime failed.\n");
        return -1;
    }
    free(ret);

    off = lseek(fd, 0, SEEK_CUR);
    if ((ret = set_offset(conn, file, off)) == NULL) {
        fprintf(stderr, "set_offset failed.\n");
        return -1;
    }
    free(ret);

#endif
    return 0;
}

static int logopen(const char *file)
{
    int ret;
#ifdef PGSQL
    time_t last;
    time_t curr;
    off_t  off = 0;

    PGconn *conn;

    if ((conn = logpg_conn()) == NULL)
        return -1;

    curr = get_cur_mtime(file);

    if ((last = get_last_mtime(conn, file)) == -1) {
        fprintf(stderr, "get_last_mtime failed.\n");
        return -1;
    }
   
    if (curr <= last) {
        fprintf(stderr, "%s is already dumped before.\n", file);
        ret = -1;
    } else 
#endif
        if ((ret = open(file, O_RDONLY)) < 0) {
        fprintf(stderr, "open failed: %s\n", strerror(errno));
        ret = -1;
    } 
#ifdef PGSQL
      else {
        if (last != 0) { 
            /* part of log has been read before, get offset */
            off = get_offset(conn, file);
            lseek(ret, off, SEEK_SET);
        }
    }

    logpg_finish(conn);
#endif
    return ret;
}

static PGconn *dbconn(void)
{
    PGconn   *conn = NULL;
#ifdef PGSQL
    char *pgbuf = NULL;
    int  pglen;

    int nfields, ntuples;
    PGresult *res;


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
#endif
    return conn;
}

static int format_time(char **buf, time_t *tmbuf)
{
    strncpy(*buf, ctime(tmbuf), TM_LEN-1);
    (*buf)[TM_LEN-1] = '\0';

    return 0;

    /*
    struct tm *ptm;
    ptm = localtime(tmbuf);
    sprintf(*buf, "%d%d%d", (1970+ptm->tm_year), ptm->tm_mon, ptm->tm_mday);
    */
}

/* eof */
