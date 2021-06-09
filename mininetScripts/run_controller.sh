#!/bin/bash
cd ../$1
echo "./controller -c $2 -p $3 -m $4 > controllerOutput 2>&1 &"
nice -n -20 ./controller -c $2 -p $3 -m $4 > controllerOutput 2>&1 &
