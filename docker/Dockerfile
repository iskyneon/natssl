# The container deliberately ships a client-only binary. Native release
# binaries retain master, client and disaster-recovery modes.
FROM --platform=$BUILDPLATFORM golang:1.22.12-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags=clientonly -mod=readonly -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o /out/natssl .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates openssl nss-tools \
    && addgroup -g 1000 natssl && adduser -D -u 1000 -G natssl natssl \
    && mkdir -p /var/lib/natssl && chown natssl:natssl /var/lib/natssl
LABEL org.opencontainers.image.source="https://github.com/iskyneon/natssl" \
      org.opencontainers.image.description="NATSSL client-only certificate store"
COPY --from=build /out/natssl /usr/local/bin/natssl
USER 1000:1000
ENTRYPOINT ["natssl"]
CMD ["--config=/etc/natssl/config.yaml"]
