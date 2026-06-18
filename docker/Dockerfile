# ---- build ----
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o /out/natssl .

# ---- runtime ----
# ---- runtime ----
FROM alpine:3.20
RUN sed -i 's|https\?://dl-cdn.alpinelinux.org/alpine|https://mirror.yandex.ru/mirrors/alpine|g' /etc/apk/repositories \
 && apk add --no-cache openssl ca-certificates
COPY --from=build /out/natssl /usr/local/bin/natssl
ENTRYPOINT ["natssl"]

