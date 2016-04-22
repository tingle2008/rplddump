
DIR=/home/ops/rpl/caiya.lww
a=`ls $DIR`
for i in $a; do
    echo -n "$a"
    sudo stat --format="%y" $DIR/$i
done
