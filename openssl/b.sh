#!/bin/bash

a=(1 2 3 4)
b=(c d e f)
c=(b c d f)
for ((i=0; i<4; i++))
do
        n=${i}
        dir=/opt/data_root/disk${a[$n]}
        disk1=/dev/sd${b[$n]}
        disk2=/dev/sd${c[$n]}
        echo mount $disk1 $dir
        echo mount $disk2 $dir
done
