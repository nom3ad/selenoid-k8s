#!/bin/sh
set -e

awk 'BEGIN{
    for(n in ENVIRON){
        if(n ~ "^file:"){
            f=substr(n,6)
            printf("creating file %s\n", f)
            system(sprintf("printenv %s >%s",n,f))
        }
    }
}' >&2

if [ $# -eq 0 ]; then
    set -- --listen=:4444 --conf=/etc/selenoid/browsers.json --video-output-dir=/opt/selenoid/video/
fi
set -x
exec /usr/bin/selenoid "$@"
