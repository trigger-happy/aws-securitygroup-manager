FROM golang:1.14.0-alpine3.11 as builder

WORKDIR /src

RUN mkdir -p /app
RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates

COPY go.mod .
COPY go.sum .
RUN go mod download
RUN go mod verify

COPY . .

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

RUN go build -ldflags "-w -s" \
      -o /app/aws-securitygroup-manager cmd/aws-securitygroup-manager.go





FROM alpine:3.11 as artifact

RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates

ENV USER=appuser UID=10001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

COPY --from=builder /app/aws-securitygroup-manager /usr/local/bin/aws-securitygroup-manager

USER appuser:appuser

ENTRYPOINT ["/usr/local/bin/aws-securitygroup-manager"]
