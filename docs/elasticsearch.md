To write results to [ElasticSearch](https://www.elastic.co/products/elasticsearch)
==================================================================================

```bash
$ docker volume create --name malice
$ docker run -d --name elasticsearch \
                -p 9200:9200 \
                -v malice:/usr/share/elasticsearch/data \
                 blacktop/elasticsearch
$ docker run --rm -v /path/to/malware:/malware:ro --link elasticsearch malice/yara -t FILE
```
