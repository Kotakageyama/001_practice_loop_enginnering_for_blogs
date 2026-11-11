FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go test ./... && CGO_ENABLED=0 go build -o /pentest ./cmd/pentest

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /pentest /usr/local/bin/pentest
ENTRYPOINT ["pentest"]
CMD ["127.0.0.1"]
