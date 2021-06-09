#!/bin/bash

interfaces=( $( ip addr | less | grep -v "^ " | cut -d' ' -f 2 | cut -d':' -f1 | grep s | grep eth ) )

for i in "${interfaces[@]}"
do
   #echo $i 
   tc qdisc del dev $i root
   #tc qdisc add dev $i root handle 1:0 htb default 10
   #tc class add dev $i parent 1:0 classid 1:10 htb rate 70Mbps ceil 70Mbps prio 1
   #tc class add dev $i parent 1:0 classid 1:01 htb rate 30Mbps ceil 10Mbps prio 0
   #tc filter add dev $i parent 1:0 prio 0 u32 match ip tos 0x01 0xff flowid 1:01

done
