# xymon
 A=`./xymonq -q xymondlog -T conn -C red | grep \|red | awk -F\| '{print $1}'`
 for i in $A;do ./xymon 127.0.0.1 "disable $i.conn -1" ;done
