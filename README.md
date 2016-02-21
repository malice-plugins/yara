![YARA-logo](https://raw.githubusercontent.com/maliceio/malice-yara/master/logo.png)
# malice-yara

[![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org)
[![Docker Stars](https://img.shields.io/docker/stars/malice/yara.svg)][hub]
[![Docker Pulls](https://img.shields.io/docker/pulls/malice/yara.svg)][hub]
[![Image Size](https://img.shields.io/imagelayers/image-size/malice/yara/latest.svg)](https://imagelayers.io/?images=malice/yara:latest)
[![Image Layers](https://img.shields.io/imagelayers/layers/malice/yara/latest.svg)](https://imagelayers.io/?images=malice/yara:latest)

Malice Yara Plugin

This repository contains a **Dockerfile** of **malice/yara** for [Docker](https://www.docker.io/)'s [trusted build](https://hub.docker.com/r/blacktop/yara/) published to the public [DockerHub](https://hub.docker.com/).

### Dependencies

* [gliderlabs/alpine:3.3](https://hub.docker.com/_/gliderlabs/alpine/)

### Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/yara/) from public [DockerHub](https://hub.docker.com): `docker pull malice/yara`

### Usage

    docker run --rm -v /path/to/rules:/rules:ro malice/yara FILE

#### Or link your own malware folder
```bash
$ docker run -v /path/to/malware:/malware:ro -v /path/to/rules:/rules:ro malice/yara FILE

Usage: yara [OPTIONS] COMMAND [arg...]

Malice YARA Plugin

Version: v0.1.0, BuildTime: 20160214

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --post, -p		POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x		proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t		output as Markdown table
  --rules "/rules"	YARA rules directory
  --help, -h		show help
  --version, -v		print the version

Commands:
  help	Shows a list of commands or help for one command

Run 'yara COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output JSON:
```json
{
  "yara": {
    "matches": [
      {
        "Rule": "_First_Publisher_Graphics_format_",
        "Namespace": "malice",
        "Tags": [],
        "Meta": {
          "description": "First Publisher Graphics format"
        },
        "Strings": [
          {
            "Name": "$1",
            "Offset": 2425,
            "Data": "AAAAAAAAHwE="
          }
        ]
      }
    ]
  }
}
```
### Sample FILTERED Output JSON:
```bash
$ cat JSON_OUTPUT | jq '.[][][] .Rule'

"_Microsoft_Visual_Cpp_v50v60_MFC_"
"_Borland_Delphi_v60__v70_"
"_dUP_v2x_Patcher__wwwdiablo2oo2cjbnet_"
"_Free_Pascal_v106_"
"_Armadillo_v171_"
```

### Sample Output STDOUT (Markdown Table):
---
#### yara
| Rule                                   | Description                                 | Offset | Data                                 | Tags |
| -------------------------------------- | ------------------------------------------- | ------ | ------------------------------------ | ---- |
| _Microsoft_Visual_Cpp_v50v60_MFC_      | Microsoft Visual C++ v5.0/v6.0 (MFC)        | 5204   | U��                                 |      |
| _Borland_Delphi_v60__v70_              | Borland Delphi v6.0 - v7.0                  | 5204   | U��                                  |      |
| _dUP_v2x_Patcher__wwwdiablo2oo2cjbnet_ | dUP v2.x Patcher --> www.diablo2oo2.cjb.net | 78     | This program cannot be run in DOS mo |      |
| _Free_Pascal_v106_                     | Free Pascal v1.06                           | 14866  | ��@O�k                            |      |
| _Armadillo_v171_                       | Armadillo v1.71                             | 23110  | U��j�h b@h�[@d�                      |      |
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
