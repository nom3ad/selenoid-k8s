GOOS?=linux
GOARCH?=amd64

PKG=github.com/nom3ad/selenoid-k8s
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
	tag=$${tag:-selenoid-k8s}; \
	docker build --build-arg TARGETOS=$(GOOS) --build-arg TARGETARCH=$(GOARCH) --build-arg BUILDPLATFORM=$(GOOS) --platform=linux/x86_64 -t $$tag -f Dockerfile .; \
	read -p "Push (Y/n)?" && [[ $${REPLY,} == "y" ]] && docker push $$tag;

