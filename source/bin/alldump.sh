#!/bin/bash

# dump logfiles in '$LOGDIR', and save results in '$LOGDIR/dump'


if [[ X$* == X"--help" || X$* == X"-?" || X$* != X ]]; then
    echo "Usage: $0"
    exit 1
fi

#-------------
PWD=`pwd`
DIR=`dirname $0 | sed 's/ *//g'`/

if [[ X$DIR != X/* ]]; then
    DIR=$PWD/$DIR
fi

#------------ conf --------------
RPLDDUMP="$DIR/rplddump"
LOGDIR=$DIR/../logfile/debug
#----------- end conf -----------

ALL=`ls $LOGDIR/*.pts-* 2>/dev/null`
SUFFIX=".dump"
SAVE=$LOGDIR/dump.$(date +%Y%m%d.%H.%M.%S)

#echo $ALL

#==============
# main
#==============
if [[ X$ALL == X ]]; then
    echo "no logfile found in dir '$LOGDIR'" > /dev/stderr
    exit 1
fi

[[ ! -d $SAVE ]] && mkdir -p $SAVE

echo starting...
for logfile in $ALL; do
    $RPLDDUMP $logfile \
        > $SAVE/`basename $logfile`$SUFFIX \
        2> $SAVE/`basename $logfile`$SUFFIX.2 
    if [[ $? == 0 ]]; then
        echo -n .
    else
        echo " "
        echo "X: $logfile"
        echo " "
    fi
done

echo " "
echo Done.
    
