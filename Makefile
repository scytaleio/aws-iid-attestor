binary_dirs := agent server
utils = github.com/goreleaser/goreleaser \
		github.com/golang/dep/cmd/dep

gopath := $(shell go env GOPATH)
.PHONY: all build dep utils test clean

build: $(binary_dirs)

utils: $(utils)

dep:
	dep ensure

$(utils): noop
	go get $@

$(binary_dirs): noop
	cd $@ && go build -i

release:
	goreleaser || true

clean:
	go clean 

noop:
