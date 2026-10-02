# syntax=docker/dockerfile:1.12
FROM golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY apps/analyzer-worker apps/analyzer-worker
COPY internal internal
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/analyzer-worker ./apps/analyzer-worker/cmd/analyzer-worker

FROM zeek/zeek@sha256:94a604186e3b47c3e10215da86eac65e36253c866a45305e2850689b3b8418d7
COPY apps/analyzer-worker/zeek/shakerproxy.zeek apps/analyzer-worker/zeek/live.zeek /etc/shakerproxy/zeek/
RUN chmod 0555 /etc/shakerproxy/zeek \
    && chmod 0444 /etc/shakerproxy/zeek/shakerproxy.zeek /etc/shakerproxy/zeek/live.zeek \
    && /usr/local/zeek/bin/zeek -a /etc/shakerproxy/zeek/shakerproxy.zeek \
    && /usr/local/zeek/bin/zeek -a /etc/shakerproxy/zeek/shakerproxy.zeek /etc/shakerproxy/zeek/live.zeek
COPY --from=build /out/analyzer-worker /usr/local/bin/analyzer-worker
USER 0:0
ENTRYPOINT ["/usr/local/bin/analyzer-worker"]
