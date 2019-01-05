![YARA-logo](https://raw.githubusercontent.com/malice-plugins/yara/master/logo.png)

# malice-yara

[![Circle CI](https://circleci.com/gh/malice-plugins/yara.png?style=shield)](https://circleci.com/gh/malice-plugins/yara) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/yara.svg)](https://hub.docker.com/r/malice/yara/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/yara.svg)](https://hub.docker.com/r/malice/yara/) [![Docker Image](https://img.shields.io/badge/docker%20image-52.9MB-blue.svg)](https://hub.docker.com/r/malice/virustotal/)

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
docker run --rm -v /path/to/rules:/rules:ro malice/yara:neo23x0 FILE
```

### Or link your own malware folder

```bash
$ docker run -v /path/to/malware:/malware:ro -v /path/to/rules:/rules:ro malice/yara:neo23x0 FILE

Usage: yara [OPTIONS] COMMAND [arg...]

Malice YARA Plugin

Version: v0.1.0, BuildTime: 20180902

Author:
  blacktop - <https://github.com/blacktop>

Options:
  --verbose, -V          verbose output
  --elasticsearch value  elasticsearch url for Malice to store results [$MALICE_ELASTICSEARCH_URL]
  --callback, -c         POST results to Malice webhook [$MALICE_ENDPOINT]
  --proxy, -x            proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  --table, -t            output as Markdown table
  --timeout value        malice plugin timeout (in seconds) (default: 60) [$MALICE_TIMEOUT]
  --rules value          YARA rules directory (default: "/rules")
  --help, -h             show help
  --version, -v          print the version

Commands:
  web   Create a Yara web service
  help  Shows a list of commands or help for one command

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
        "Rule": "APT30_Generic_7",
        "Namespace": "malice",
        "Tags": null,
        "Meta": {
          "author": "Florian Roth",
          "date": "2015/04/13",
          "description": "FireEye APT30 Report Sample",
          "hash0": "2415f661046fdbe3eea8cd276b6f13354019b1a6",
          "hash1": "e814914079af78d9f1b71000fee3c29d31d9b586",
          "hash2": "0263de239ccef669c47399856d481e3361408e90",
          "license": "https://creativecommons.org/licenses/by-nc/4.0/",
          "reference": "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf",
          "super_rule": 1
        },
        "Strings": [
          {
            "Name": "$s1",
            "Offset": 29824,
            "Data": "WGphcG9yXyphdGE="
          },
          {
            "Name": "$s2",
            "Offset": 29848,
            "Data": "WGphcG9yX28qYXRh"
          },
          {
            "Name": "$s4",
            "Offset": 29864,
            "Data": "T3VvcGFp"
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

#### Yara

| Rule              | Description                 | Offset   | Data                    | Tags |
| ----------------- | --------------------------- | -------- | ----------------------- | ---- |
| `APT30_Generic_7` | FireEye APT30 Report Sample | `0x7480` | `&#34;Xjapor_*ata&#34;` | []   |

> NOTE: **Data** truncated to 25 characters

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
