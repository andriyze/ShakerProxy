# syntax=docker/dockerfile:1.12
FROM golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY apps/control-api apps/control-api
COPY internal internal
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/control-api ./apps/control-api/cmd/control-api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/control-api /usr/local/bin/control-api
COPY schemas /usr/share/shakerproxy/schemas
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/control-api"]
