#!/bin/bash

grep $1 /app/jet/scripts/klassen/psaccesslog.txt | tail -n 100 > /app/jet/scripts/klassen/$1.txt