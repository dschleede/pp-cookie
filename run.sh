#!/bin/bash
#
for number in {1..20000}
do
    ./decode `./encode`
    sleep 1
done
