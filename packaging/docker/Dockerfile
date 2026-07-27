# AEGIS-SIGMA Community Edition — Multi-arch Docker build
# Usage: docker buildx build --platform linux/amd64,linux/arm64 -t aegis-sigma .

# Stage 1: Build Go binaries
FROM debian:bookworm-slim AS go-builder
ARG TARGETARCH
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
RUN wget -q https://go.dev/dl/go1.24.4.linux-${TARGETARCH}.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
WORKDIR /build
COPY engine/ .
RUN for cmd in shield soul geoip trap bridge; do \
    GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" \
    -o aegis-$cmd ./cmd/$cmd/; done

# Stage 2: Build C engine
FROM gcc:13 AS c-builder
ARG TARGETARCH
RUN apt-get update && apt-get install -y libcjson-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY c-engine/ .
RUN gcc -O2 -Wall -o aegis-c-engine shield_soul.c model.c spiral.c groq_teacher.c -lm -lcjson -lpthread

# Stage 3: Package as deb
FROM debian:bookworm-slim AS packager
ARG TARGETARCH
RUN apt-get update && apt-get install -y dpkg-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /deb
COPY packaging/deb/DEBIAN/ DEBIAN/
RUN mkdir -p usr/local/bin usr/bin usr/share/aegis-sigma/training usr/lib/aegis-sigma
COPY --from=go-builder /build/aegis-* usr/local/bin/
COPY --from=c-builder /build/aegis-c-engine usr/bin/
COPY training/*.py usr/share/aegis-sigma/training/
COPY config/config.yaml usr/share/aegis-sigma/config.yaml
COPY scripts/setup-wizard.sh usr/lib/aegis-sigma/setup-wizard.sh
COPY .env.example usr/share/aegis-sigma/.env.example
RUN mkdir -p /output && dpkg-deb --build . /output/aegis-sigma-community_1.0.0_${TARGETARCH}.deb

# Stage 4: Runtime
FROM debian:bookworm-slim
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 libsqlite3-0 libgcc-s1 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=go-builder /build/aegis-* /usr/local/bin/
COPY --from=c-builder /build/aegis-c-engine /usr/bin/
COPY .env.example /etc/aegis-sigma/.env
EXPOSE 3000 3007 4040 8086 8899
CMD ["/usr/local/bin/aegis-shield"]
