ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM alpine:3

RUN apk add -U ca-certificates tzdata mailcap && rm -Rf /var/cache/apk/*

ARG TARGETARCH
COPY dist/selenoid_linux_$TARGETARCH /usr/bin/selenoid
COPY config/browsers.json /etc/selenoid/browsers.json
COPY entrypoint.sh /entrypoint.sh

EXPOSE 4444
ENTRYPOINT ["./entrypoint.sh"]
