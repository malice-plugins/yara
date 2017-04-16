FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

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
  && git clone --recursive --branch v3.5.0 https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && ./configure --enable-cuckoo \
                 --enable-magic \
                 --with-crypto \
  && make \
  && make install \
  && rm -rf /tmp/* \
  && apk del --purge .build-deps

# Install malice plugin
COPY . /go/src/github.com/maliceio/malice-yara
RUN apk --update add --no-cache -t .build-deps \
                                    build-base \
                                    mercurial \
                                    musl-dev \
                                    openssl \
                                    bash \
                                    wget \
                                    git \
                                    gcc \
                                    go \
  && echo "===> Building scan Go binary..." \
  && cd /go/src/github.com/maliceio/malice-yara \
  && export GOPATH=/go \
  && export CGO_CFLAGS="-I/usr/local/include" \
  && export CGO_LDFLAGS="-L/usr/local/lib" \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* \
  && apk del --purge .build-deps

COPY rules /rules

VOLUME ["/malware"]
VOLUME ["/rules"]

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","scan"]
CMD ["--help"]
