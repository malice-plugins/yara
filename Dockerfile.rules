FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/yara.git"
LABEL malice.plugin.category="av"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

ENV YARA 3.9.0

# Install Yara
RUN apk --update add --no-cache openssl file bison jansson ca-certificates
RUN apk --update add --no-cache -t .build-deps \
  openssl-dev \
  jansson-dev \
  build-base \
  libc-dev \
  file-dev \
  automake \
  autoconf \
  libtool \
  flex \
  git \
  gcc \
  && echo "===> Install Yara from source..." \
  && cd /tmp \
  && git clone --recursive --branch v${YARA} https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && sync \
  && ./configure --enable-magic \
  --enable-cuckoo \
  --enable-dotnet \
  && make \
  && make install \
  && rm -rf /tmp/* \
  && apk del --purge .build-deps

# Install malice plugin
COPY . /go/src/github.com/maliceio/malice-yara
RUN apk --update add --no-cache -t .build-deps \
  openssl-dev \
  jansson-dev \
  build-base \
  mercurial \
  musl-dev \
  openssl \
  bash \
  wget \
  git \
  gcc \
  dep \
  go \
  && echo "===> Building scan Go binary..." \
  && echo " * adding yara rules" \
  && cd /tmp \
  && git clone https://github.com/Yara-Rules/rules.git \
  && mkdir /rules \
  && mv rules /rules \
  && echo " * remove broken rules" \
  && find /rules -not -name "*.yar" -type f -delete \
  # && rm /rules/yara/general_cloaking.yar \
  && cd /go/src/github.com/maliceio/malice-yara \
  && export GOPATH=/go \
  && export CGO_CFLAGS="-I/usr/local/include" \
  && export CGO_LDFLAGS="-L/usr/local/lib -lyara" \
  && export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
  && go version \
  && dep ensure \
  && CGO_ENABLED=1 go build -ldflags "-s -w -X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","scan"]
CMD ["--help"]
