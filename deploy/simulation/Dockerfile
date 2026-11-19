FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -g 10001 fleetops && adduser -D -u 10001 -G fleetops fleetops && mkdir /data && chown fleetops:fleetops /data && chmod 0700 /data
COPY --chmod=0555 a-agent/build/fleetops-a /usr/local/bin/fleetops-a
COPY --chmod=0555 b-monitor/build/fleetops-b /usr/local/bin/fleetops-b
COPY --chmod=0555 deploy/simulation/entrypoint.sh /usr/local/bin/fleetops-simulation
COPY deploy/simulation/test-configs/ /configs/
USER 10001:10001
VOLUME /data
ENTRYPOINT ["/usr/local/bin/fleetops-simulation"]
