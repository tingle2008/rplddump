OUT := rplddump

BIN := ./bin
INC := ./include
OPT := -lreadline -lncurses
LOG := logfile
#PGINC := /usr/local/pgsql/include
#PGLIB := /usr/local/pgsql/lib 
#PGOPT := -lpq

COMMSRC := src/dumpfunc.c src/rplddump.c
#COMMSRC += src/logoffset.c 

#all: install
all: rplddump

rplddump: clean src/main.c
	gcc -g -o $@ -I${INC} -I${PGINC} -L${PGLIB} ${OPT} ${PGOPT}  ${COMMSRC} src/main.c

walklog: clean src/rplddump.c
	gcc -g -o $@ -I${INC} -I${PGINC} -L${PGLIB} ${OPT} ${PGOPT}  ${COMMSRC} src/rplddump.c


install: rplddump
	@mv ${OUT} ${BIN}/
	@chmod +x ${BIN}/${OUT}

exec:
	${BIN}/${OUT} ${LOG}/log >out.1 2>out.2

thres: clean src/update_thres.c src/logoffset.c
	gcc -g -o update_thres -I${INC} -I${PGINC} -L${PGLIB} ${PGOPT} src/update_thres.c src/logoffset.c

test: clean src/test.c src/logoffset.c
	gcc -g -o test -I${INC} -I${PGINC} -L${PGLIB} ${PGOPT} src/test.c src/logoffset.c


memcheck: install
	valgrind -q --leak-check=full --trace-children=yes\
             ${BIN}/${OUT} ${LOG}/log 
#             --show-reachable=yes ${BIN}/${OUT} ${LOG}/log 

clean:
	@rm -rf rplddump store out.1 out.2 instream_tmp.* test bin/rplddump
	
