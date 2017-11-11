REPO=malice-plugins/yara
ORG=malice
NAME=yara
VERSION=$(shell cat VERSION)

all: build size test

build: ## Build docker image
	docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: dev
dev: ## Build dev docker image
	docker build -f Dockerfile.dev -t $(ORG)/$(NAME):dev .

.PHONY: size
size: build ## Get built image size
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

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

.PHONY: run
run: stop ## Run docker container
	@docker run --init -d --name $(NAME) -p 9200:9200 $(ORG)/$(NAME):$(VERSION)

.PHONY: ssh
ssh: ## SSH into docker image
	@docker run -it --rm --entrypoint=sh $(ORG)/$(NAME):$(VERSION)

.PHONY: ssh-dev
ssh-dev: ## SSH into docker image
	@docker run -it --rm --entrypoint=sh $(ORG)/$(NAME):dev

.PHONY: stop
stop: ## Kill running docker containers
	@docker rm -f $(NAME) || true

circle: ci-size
	@sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/SIZE)-blue/' README.md
	@echo "===> Image size is: $(shell cat .circleci/SIZE)"

ci-build:
	@echo "===> Getting CircleCI build number"
	@http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num

ci-size: ci-build
	@echo "===> Getting image build size from CircleCI"
	@http "$(shell http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq '.[].url')" > .circleci/SIZE

clean: ## Clean docker image and stop all running containers
	docker-clean stop
	docker rmi $(ORG)/$(NAME):$(VERSION) || true
	docker rmi $(ORG)/$(NAME):dev || true
	rm befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 || true

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
