#!/bin/bash

mkdir $2
mn -c && python ${4}node.py --controller $3 --monitoring 3 -d $2 -n $1
mv ../$3/controllerOutput $2/$1/
