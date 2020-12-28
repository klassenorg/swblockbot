#!/bin/bash

for i in {01..22};
do ssh weblogic@atg-ps$i-prod 'sedtime=$(date --date "-10min" +"%d\/%b\/%Y:%H:%M:%S") && sed -n "/$sedtime/,$ p" /app/nginx/logs/atg-access.log' >> /app/jet/scripts/klassen/psaccesslog.txt &
done
wait