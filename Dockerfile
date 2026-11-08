# The default builds from source. CI selects ARTIFACT_STAGE=release so the
# published images contain exactly the already tested native release binaries.
ARG ARTIFACT_STAGE=builder
FROM golang:1.23.1-alpine3.20 AS builder
WORKDIR /src
RUN apk add --no-cache build-base curl unzip python3 binutils git
COPY . .
ARG TARGETARCH
ARG TARGETVARIANT
RUN mkdir -p /package/bin \
    && CGO_ENABLED=1 CGO_CFLAGS=-D_LARGEFILE64_SOURCE go build -trimpath \
       -tags 'netgo,osusergo,sqlite_omit_load_extension' \
       -ldflags '-s -w -linkmode external -extldflags -static' -o /package/x-ui . \
    && ./DockerInit.sh "$TARGETARCH" "$TARGETVARIANT" /package/bin \
    && cp x-ui.sh LICENSE /package/

FROM alpine:3.22 AS release
ARG TARGETARCH
ARG TARGETVARIANT
COPY release-packages/ /archives/
RUN platform="$TARGETARCH"; \
    if [ "$TARGETARCH" = arm ]; then platform="arm${TARGETVARIANT:-v7}"; fi; \
    mkdir /package /unpack \
    && tar -xzf "/archives/x-ui-linux-$platform.tar.gz" -C /unpack \
    && cp -a /unpack/x-ui/. /package/

FROM ${ARTIFACT_STAGE} AS artifact
FROM alpine:3.22
ENV TZ=Asia/Shanghai PATH=/app/bin:$PATH
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata fail2ban bash iproute2 iptables openresolv \
    && rm -f /etc/fail2ban/jail.d/alpine-ssh.conf
COPY --from=artifact /package/ /app/
COPY DockerEntrypoint.sh /app/DockerEntrypoint.sh
RUN chmod 755 /app/DockerEntrypoint.sh /app/x-ui /app/x-ui.sh \
    && ln -s /app/x-ui.sh /usr/bin/x-ui
VOLUME ["/etc/x-ui"]
ENTRYPOINT ["/app/DockerEntrypoint.sh"]
CMD ["/app/x-ui"]
