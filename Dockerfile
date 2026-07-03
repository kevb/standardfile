# build stage
FROM golang:1.26-alpine AS build-env

RUN apk add --update --no-cache ca-certificates git

WORKDIR /src

ARG VERSION=dev
ARG REVISION=none
ARG DATE=unknown

ENV CGO_ENABLED=0
ENV GO111MODULE=on
ENV GOPROXY=https://proxy.golang.org

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build \
  -ldflags "-s -w -X main.version=${VERSION} -X main.revision=${REVISION} -X main.date=${DATE}" \
  -o /dist/standardfile ./cmd/standardfile

# final stage
FROM alpine:3

ENV DATABASE_PATH /data/database

RUN apk add --update --no-cache ca-certificates && \
  mkdir -p ${DATABASE_PATH}

COPY --from=build-env /dist/standardfile /usr/local/bin/

EXPOSE 5000
CMD ["standardfile", "server", "-c", "/etc/standardfile/standardfile.yml"]
