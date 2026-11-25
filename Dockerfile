# Build
FROM golang:1.27-alpine AS build-env
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sharefinder .

# Release
FROM alpine:latest
RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
RUN adduser -D -u 1000 -s /sbin/nologin app
USER app
COPY --from=build-env /app/sharefinder /usr/local/bin

ENTRYPOINT ["sharefinder"]
