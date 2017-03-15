#!/bin/bash

sed -i 's@APP_ID@'"$APP_ID"'@' /home/r/mod_perimeterx/t/conf/extra.conf
sed -i 's@TOKEN@'"$AUTH_TOKEN"'@' /home/r/mod_perimeterx/t/conf/extra.conf

/home/r/mod_perimeterx/t/TEST -v
