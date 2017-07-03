REPO=malice-plugins/yara
ORG=malice
NAME=yara
VERSION=$(shell cat VERSION)

all: build size test

build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)%20MB-blue/' README.md

test:
	docker run --rm $(ORG)/$(NAME):$(VERSION) --help
	test -f befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 || wget https://github.com/maliceio/malice-av/raw/master/samples/befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408
	docker run --rm -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -t befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 > SAMPLE.md
	# docker run --rm -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408 > results.json
	# cat results.json | jq .
	# rm befb88b89c2eb401900a68e9f5b78764203f2b48264fcc3f7121bf04a57fd408

circle:
	http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num
	http "$(shell http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq '.[].url')" > .circleci/SIZE
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/SIZE)-blue/' README.md

.PHONY: build size tags test circle
