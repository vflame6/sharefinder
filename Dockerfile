# Build
FROM golang:1.24-alpine AS build-env
RUN apk add build-base
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o sharefinder .

# Release
FROM alpine:latest
RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
RUN adduser -D -u 1000 -s /sbin/nologin app
USER app
COPY --from=build-env /app/sharefinder /usr/local/bin

ENTRYPOINT ["sharefinder"]
