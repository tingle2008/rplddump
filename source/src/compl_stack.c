#include <rpl_readline.h>

#define COMPL_MAX_LOG 1000

static char *compl_table[COMPL_MAX_LOG];
static int top_compl_table;
static int index_compl_table;

int init_compl_table(void)
{
    top_compl_table = 0;
    index_compl_table = 0;

    return 0;
}

char *compl_strdup(const char *word)
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
    }
    strncpy(ret, word, len);
    ret[len] = '\0';

    return ret;
}

int compl_put(const char *word)
{
    int ret = -1;
    char *pword;

    if (top_compl_table >= COMPL_MAX_LOG) {
        fprintf(stderr, "BUG: 'COMPL_MAX_LOG("COMPL_MAX_LOG")' too small.\n", );
        return -1;
    }

    if ((pword = compl_strdup(word)) == NULL) {
        return -1;
    }

    compl_table[top_compl_table++] = pword;
    return 0;
}

char *compl_get(void)
{
    if ((index_compl_table > top_compl_table) ||
        (index_compl_table <= 0))
    {
        fprintf(stderr, "bad index_compl_table(%d).\n, index_compl_table");
        return NULL;
    }
    
    return compl_table[--index_compl_table];
}

char **rpl_completion(const char *text, int start, int end)
{
    char **matches = NULL;

    if (start == 0) {
        matches = rl_completion_matches((char *)text, &rpl_generator);
    } else {
        rl_bind_key('\t', rl_abort);
    }

    return matches;
}

char *rpl_generator(const char *text, int state)
{
    char *name = NULL;
    static size_t len;

    if (state == 0) {
        index_compl_table = top_compl_table;
        len = strlen(text);
    }
  
    while ((index_compl_table <= top_compl_table) && (index_compl_table > 0)) {
        if ((name = compl_get()) != NULL) {
            if (strncmp(name, text, len) == 0) {
                return (compl_strdup(name));
            }
        }
    }
    
    return (char *)NULL; 
}
