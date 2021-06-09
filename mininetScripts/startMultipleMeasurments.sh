#!/bin/bash

for i in {1..30}
do
./startMeasurments.sh $i $1 $2 $3
sleep 5
done
