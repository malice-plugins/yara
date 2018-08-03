# Create a `yara` scan micro-service

```bash
$ docker run -d -p 3993:3993 malice/yara web

INFO[0000] web service listening on port :3993
```

## Now you can perform scans like so

```bash
$ http -f localhost:3993/scan malware@/path/to/evil/malware
```

> **NOTE:** I am using **httpie** to POST to the malice micro-service

```bash
HTTP/1.1 200 OK
Content-Length: 124
Content-Type: application/json; charset=UTF-8
Date: Sat, 21 Jan 2017 05:39:29 GMT

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
