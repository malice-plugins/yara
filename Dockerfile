FROM malice/alpine:tini

MAINTAINER blacktop, https://github.com/blacktop

ADD https://raw.githubusercontent.com/maliceio/go-plugin-utils/master/scripts/upgrade-alpine-go.sh /tmp/upgrade-alpine-go.sh

COPY . /go/src/github.com/maliceio/malice-yara
COPY rules /rules
RUN apk-install openssl file bison jansson ca-certificates
RUN apk-install -t .build-deps go git mercurial autoconf automake file-dev flex gcc git jansson-dev libc-dev libtool build-base openssl-dev musl-dev wget bash \
  && set -x \
  && echo "Install Yara from source..." \
  && cd /tmp/ \
  && git clone --recursive --branch v3.5.0 https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && ./configure --enable-cuckoo \
                 --enable-magic \
                 --with-crypto \
  && make \
  && make install \
  && chmod +x /tmp/upgrade-alpine-go.sh \
  && ./tmp/upgrade-alpine-go.sh \
  && echo "Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-yara \
  && export GOPATH=/go \
  && export PATH=$GOPATH/bin:/usr/local/go/bin:$PATH \
  && export CGO_CFLAGS="-I/usr/local/include" \
  && export CGO_LDFLAGS="-L/usr/local/lib" \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan \
  && rm -rf /go /usr/local/go /usr/lib/go /tmp/* \
  && apk del --purge .build-deps

VOLUME ["/malware"]
VOLUME ["/rules"]

WORKDIR /malware

ENTRYPOINT ["gosu","malice","/sbin/tini","--","scan"]

CMD ["--help"]
