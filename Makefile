REPO=malice-plugins/yara
ORG=malice
NAME=yara
VERSION=$(shell cat VERSION)

all: build size test

build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

test:
	@echo "===> Starting elasticsearch"
	@docker rm -f elasticsearch || true
	@docker run --init -d --name elasticsearch -p 9200:9200 blacktop/elasticsearch
	@echo "===> ${NAME} --help"
	@sleep 10; docker run --rm $(ORG)/$(NAME):$(VERSION)
	@echo "===> ${NAME} malware test"
	@test -f befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 || wget https://github.com/maliceio/malice-av/raw/master/samples/befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408
	@docker run --rm --link elasticsearch -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 | jq . > docs/results.json
	@cat docs/results.json | jq .
	@echo "===> ${NAME} pull MarkDown from elasticsearch results"			
	@http localhost:9200/malice/_search | jq . > docs/elastic.json
	@cat docs/elastic.json | jq -r '.hits.hits[] ._source.plugins.av.${NAME}.markdown' > docs/SAMPLE.md
	@docker rm -f elasticsearch

circle: ci-size
	@sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/SIZE)-blue/' README.md
	@echo "===> Image size is: $(shell cat .circleci/SIZE)"

ci-build:
	@echo "===> Getting CircleCI build number"
	@http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num

ci-size: ci-build
	@echo "===> Getting image build size from CircleCI"
	@http "$(shell http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq '.[].url')" > .circleci/SIZE

clean:
	docker-clean stop
	docker rmi $(ORG)/$(NAME):$(VERSION)
	rm befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 || true