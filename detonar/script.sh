#! /bin/bash


for i in {1..17}
do
	echo " " >> statistics.txt
	cat 101.csv | cut -d ',' --fields="2,3" | grep SENSOR-$i | sort | uniq -c >> statistics.txt
done
