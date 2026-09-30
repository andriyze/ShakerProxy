# syntax=docker/dockerfile:1.12
FROM golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY apps/ingestd apps/ingestd
COPY apps/forwarderd apps/forwarderd
COPY apps/mitm-event-forwarderd apps/mitm-event-forwarderd
COPY apps/inventory-cloud-forwarderd apps/inventory-cloud-forwarderd
COPY internal internal
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/ingestd ./apps/ingestd/cmd/ingestd
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/forwarderd ./apps/forwarderd/cmd/forwarderd
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/mitm-event-forwarderd ./apps/mitm-event-forwarderd/cmd/mitm-event-forwarderd
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/inventory-cloud-forwarderd ./apps/inventory-cloud-forwarderd/cmd/inventory-cloud-forwarderd

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ingestd /usr/local/bin/ingestd
COPY --from=build /out/forwarderd /usr/local/bin/forwarderd
COPY --from=build /out/mitm-event-forwarderd /usr/local/bin/mitm-event-forwarderd
COPY --from=build /out/inventory-cloud-forwarderd /usr/local/bin/inventory-cloud-forwarderd
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ingestd"]
