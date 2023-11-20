# GitHub action dockerfile
# Requires docker experimental features as buildx and BuildKit so not suitable for developers regular use.
# https://docs.docker.com/develop/develop-images/build_enhancements/#to-enable-buildkit-builds

###########################
# Build binaries stage
###########################
FROM --platform=$BUILDPLATFORM golang:1.21.4-alpine3.17 AS build
ADD . /app
WORKDIR /app
# Arguments required to build binaries targetting the correct OS and CPU architectures
ARG TARGETOS TARGETARCH
# Actually building the binaries
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go install -v . ./cmd/...

###########################
# Build docker image stage
###########################
FROM alpine:3.17
COPY --from=build /go/bin /bin
# 9901  Mainnet Peercoin peer-to-peer port
# 9902  Mainet RPC port
EXPOSE 9901 9902
ENTRYPOINT ["ppcd"]
