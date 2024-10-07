FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/ubi-minimal:latest AS collect

RUN mkdir /download
COPY ./* /download/
WORKDIR /download
RUN \
    ls -lR && \
    mkdir -p linux/arm64 && \
    mkdir -p linux/amd64 && \
    mv sbomsleuth-aarch64-unknown-linux-gnu linux/arm64/sbom && \
    mv sbomsleuth-x86_64-unknown-linux-gnu linux/amd64/sbom

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

LABEL org.opencontainers.image.source="https://github.com/JimFuller-RedHat/sbomsleuth"

ARG TARGETPLATFORM

RUN echo ${TARGETPLATFORM}

COPY --from=collect /download/${TARGETPLATFORM}/sbomsleuth /usr/local/bin/

RUN \
    chmod a+x /usr/local/bin/sbomsleuth
