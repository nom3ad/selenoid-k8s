GOOS?=linux
GOARCH?=amd64

PKG=github.com/nom3ad/selenoid-ng
TAG ?= $(shell cat TAG)
REPO_INFO ?= $(shell git config --get remote.origin.url || basename $$(pwd))
COMMIT_SHA ?= git-$(shell git rev-parse --short HEAD)
BUILD_TIMESTAMP ?= $(shell date --utc --iso-8601=minutes)

BUILD_OUTPUT?=dist/selenoid_$(GOOS)_$(GOARCH)

LDFLAGS="-X main.buildStamp=$(BUILD_TIMESTAMP) -X main.gitRevision=$(COMMIT_SHA) -s -w"

all: build

.PHONY: build
build:
	@set -e; \
	GOOS=$(GOOS) \
	GOARCH=$(GOARCH) \
	CGO_ENABLED=0 \
	go build -v -ldflags=$(LDFLAGS) -o $(BUILD_OUTPUT) . && \
	file $(BUILD_OUTPUT); ls -alh $(BUILD_OUTPUT); 

.PHONY: image
image: build
	@set -e; \
	tag=$${tag:-selenoid-ng}; \
	docker build --build-arg TARGETOS=$(GOOS) --build-arg TARGETARCH=$(GOARCH) --build-arg BUILDPLATFORM=$(GOOS) --platform=linux/x86_64 -t $$tag -f Dockerfile .; \
	read -p "Push (Y/n)?" && [[ $${REPLY,} == "y" ]] && docker push $$tag;

.PHONY: run-k8s
run-k8s:
	@set -x; \
	go run . -orchestrator kubernetes $$args

.PHONY: run-ecs
run-ecs:
	@set -x; \
	go run .  -orchestrator aws-ecs $$args

.PHONY: run-demo
run-demo:
	python demo/main.py

.PHONY: run-selenoid-ui
run-selenoid-ui:
	docker run --rm --name selenoid-ui -it --net=host aerokube/selenoid-ui