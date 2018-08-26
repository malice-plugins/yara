![YARA-logo](https://raw.githubusercontent.com/malice-plugins/yara/master/logo.png)

# malice-yara

[![Circle CI](https://circleci.com/gh/malice-plugins/yara.png?style=shield)](https://circleci.com/gh/malice-plugins/yara) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/yara.svg)](https://hub.docker.com/r/malice/yara/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/yara.svg)](https://hub.docker.com/r/malice/yara/) [![Docker Image](https://img.shields.io/badge/docker%20image-51.9MB-blue.svg)](https://hub.docker.com/r/malice/virustotal/)

Malice Yara Plugin

This repository contains a **Dockerfile** of the [Yara](http://virustotal.github.io/yara/) malice plugin **malice/yara**.

### Dependencies

- [malice/alpine](https://hub.docker.com/r/malice/alpine/)

## Image Tags

```
REPOSITORY          TAG                 SIZE
malice/yara         latest              51.9MB
malice/yara         0.1.0               51.9MB
malice/yara         neo23x0             51.3MB
```

> **NOTE:** tag `neo23x0` contains all of the [signature-base](https://github.com/Neo23x0/signature-base/tree/master/yara) rules

## Installation

1.  Install [Docker](https://www.docker.io/).
2.  Download [trusted build](https://hub.docker.com/r/malice/yara/) from public [DockerHub](https://hub.docker.com): `docker pull malice/yara`

## Usage

```
docker run --rm -v /path/to/rules:/rules:ro malice/yara FILE
```

### Or link your own malware folder

```bash
$ docker run -v /path/to/malware:/malware:ro -v /path/to/rules:/rules:ro malice/yara FILE

Usage: yara [OPTIONS] COMMAND [arg...]

Malice YARA Plugin

Version: v0.1.0, BuildTime: 20170123

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V		verbose output
  --elasitcsearch value elasitcsearch address for Malice to store results [$MALICE_ELASTICSEARCH]
  --timeout value       malice plugin timeout (in seconds) (default: 60) [$MALICE_TIMEOUT]
  --callback, -c	    POST results to Malice webhook [$MALICE_ENDPOINT]
  --timeout value       malice plugin timeout (in seconds) (default: 60) [$MALICE_TIMEOUT]
  --proxy, -x		proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t		output as Markdown table
  --rules value		YARA rules directory (default: "/rules")
  --help, -h		show help
  --version, -v		print the version

Commands:
  help	Shows a list of commands or help for one command

Run 'yara COMMAND --help' for more information on a command.
```

This will output to stdout and POST to malice results API webhook endpoint.

## Sample Output

### [JSON](https://github.com/malice-plugins/yara/blob/master/docs/results.json)

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

### FILTERED Output JSON:

```bash
$ cat JSON_OUTPUT | jq '.[][][] .Rule'

"_Microsoft_Visual_Cpp_v50v60_MFC_"
"_Borland_Delphi_v60__v70_"
"_dUP_v2x_Patcher__wwwdiablo2oo2cjbnet_"
"_Free_Pascal_v106_"
"_Armadillo_v171_"
```

### [Markdown](https://github.com/malice-plugins/yara/blob/master/docs/SAMPLE.md)

---

#### yara

| Rule                                     | Description                                 | Offset | Data                                 | Tags |
| ---------------------------------------- | ------------------------------------------- | ------ | ------------------------------------ | ---- |
| _Microsoft_Visual_Cpp_v50v60_MFC_        | Microsoft Visual C++ v5.0/v6.0 (MFC)        | 5204   | U��                                  |      |
| _Borland_Delphi_v60\_\_v70_              | Borland Delphi v6.0 - v7.0                  | 5204   | U��                                  |      |
| _dUP_v2x_Patcher\_\_wwwdiablo2oo2cjbnet_ | dUP v2.x Patcher --> www.diablo2oo2.cjb.net | 78     | This program cannot be run in DOS mo |      |
| _Free_Pascal_v106_                       | Free Pascal v1.06                           | 14866  | ��@O�k                               |      |
| _Armadillo_v171_                         | Armadillo v1.71                             | 23110  | U��j�h b@h�[@d�                      |      |

---

## Documentation

- [To write results to ElasticSearch](https://github.com/malice-plugins/yara/blob/master/docs/elasticsearch.md)
- [To create a Yara scan micro-service](https://github.com/malice-plugins/yara/blob/master/docs/web.md)
- [To post results to a webhook](https://github.com/malice-plugins/yara/blob/master/docs/callback.md)

## TODO

- [ ] add rules _(tagged?)_ from https://github.com/Yara-Rules/rules
- [x] add rules _(tagged?)_ from https://github.com/Neo23x0/signature-base

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/malice-plugins/yara/issues/new) and I'll get right on it.

## CHANGELOG

See [`CHANGELOG.md`](https://github.com/malice-plugins/yara/blob/master/CHANGELOG.md)

## Contributing

[See all contributors on GitHub](https://github.com/malice-plugins/yara/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/malice-plugins/yara/blob/master/CHANGELOG.md) and submit a [Pull Request on GitHub](https://help.github.com/articles/using-pull-requests/).

## License

MIT Copyright (c) 2016 **blacktop**
