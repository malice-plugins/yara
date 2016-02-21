FROM gliderlabs/alpine:3.3

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-yara
RUN apk-install openssl file jansson
RUN apk-install -t build-deps go git mercurial autoconf automake file-dev flex gcc git jansson-dev libc-dev libtool make openssl-dev \
  && set -x \
  && cd /tmp/ \
  && git clone --recursive --branch v3.4.0 git://github.com/plusvic/yara \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && ./configure --enable-cuckoo \
                 --enable-magic \
                 --with-crypto \
  && make \
  && make install \
  && echo "Move example rules into rules directory..." \
  && mv /go/src/github.com/maliceio/malice-yara/rules /rules \
  && echo "Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-yara \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan \
  && rm -rf /go \
  && rm -rf /tmp/* \
  && apk del --purge build-deps

VOLUME ["/malware"]
VOLUME ["/rules"]

WORKDIR /malware

ENTRYPOINT ["/bin/scan"]

CMD ["--help"]
