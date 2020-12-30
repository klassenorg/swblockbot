#!/bin/bash

grep "\-PROD\|$1" /app/jet/scripts/klassen/psaccesslog.txt | awk -F '"' '{print $1 " " $2 " " $6}'  > /app/jet/scripts/klassen/$1.txt