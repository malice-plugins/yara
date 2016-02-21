![YARA-logo](https://raw.githubusercontent.com/maliceio/malice-yara/master/logo.png)
# malice-yara

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)
[![Docker Stars](https://img.shields.io/docker/stars/malice/yara.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/malice/yara.svg)][hub]
[![Image Size](https://img.shields.io/imagelayers/image-size/malice/yara/latest.svg)](https://imagelayers.io/?images=malice/yara:latest)
[![Image Layers](https://img.shields.io/imagelayers/layers/malice/yara/latest.svg)](https://imagelayers.io/?images=malice/yara:latest)

Malice Yara Plugin

This repository contains a **Dockerfile** of **malice/yara** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/yara/) published to the public [DockerHub](https://index.docker.io/).

> **WARNING:** Work in progress.  Not ready yet.

### Dependencies

* [gliderlabs/alpine:3.3](https://index.docker.io/_/gliderlabs/alpine/)


### Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/yara/) from public [DockerHub](https://hub.docker.com): `docker pull malice/yara`

### Usage

    docker run --rm malice/yara FILE

```bash
Usage: yara [OPTIONS] COMMAND [arg...]

Malice yara Plugin

Version: v0.1.0, BuildTime: 20160214

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --table, -t	output as Markdown table
  --post, -p	POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x	proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --help, -h	show help
  --version, -v	print the version

Commands:
  help		Shows a list of commands or help for one command

Run 'yara COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output JSON:
```json
{
  "yara": {
  }
}
```
### Sample Output STDOUT (Markdown Table):
---
#### yara

---
### To Run on OSX
 - Install [Homebrew](http://brew.sh)

```bash
$ brew install caskroom/cask/brew-cask
$ brew cask install virtualbox
$ brew install docker
$ brew install docker-machine
$ docker-machine create --driver virtualbox malice
$ eval $(docker-machine env malice)
```

### Documentation

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-av/issues/new) and I'll get right on it.

### Credits

### License
MIT Copyright (c) 2016 **blacktop**

[hub]: https://hub.docker.com/r/malice/yara/
