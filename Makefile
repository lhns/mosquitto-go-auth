CFLAGS := -I/usr/local/include -fPIC
LDFLAGS := -shared

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -undefined dynamic_lookup
endif

all:
	@echo "Bulding for $(UNAME_S)"
	env CGO_CFLAGS="$(CFLAGS)" go build -buildmode=c-archive go-auth.go
	env CGO_CFLAGS="$(CFLAGS)" CGO_LDFLAGS="$(LDFLAGS)" go build -buildmode=c-shared -o go-auth.so
	go build pw-gen/pw.go

without-vcs:
	@echo "Bulding for $(UNAME_S)"
	env CGO_CFLAGS="$(CFLAGS)" go build -buildvcs=false -buildmode=c-archive go-auth.go
	env CGO_CFLAGS="$(CFLAGS)" CGO_LDFLAGS="$(LDFLAGS)" go build -buildvcs=false -buildmode=c-shared -o go-auth.so
	go build -buildvcs=false pw-gen/pw.go

# Custom plugin fixture for backends tests. It uses the same go tool and -race as the tests,
# because a Go plugin must match the host binary. No "test" tag: that tag is for test binaries only.
fixture:
	cd plugin && $(MAKE) GOFLAGS=-race

# Fast suite: no external services. Root tests need the mosquitto headers (use the Docker image).
test: all fixture
	go test -race -count=1 -buildvcs=false -tags test -timeout=60s ./...

# Needs the services started by run-test-in-docker.sh.
test-integration: all fixture
	go test -race -count=1 -buildvcs=false -tags 'test,integration' -timeout=5m ./...

build-docker-test:
	docker build -t mosquitto-go-auth.test -f Dockerfile.runtest .

run-docker-test:
	docker run --rm -ti mosquitto-go-auth.test ./run-test-in-docker.sh

service:
	@echo "Generating gRPC code from .proto files"
	@go generate grpc/grpc.go

clean:
	rm -f plugin/plugin.so
	rm -f go-auth.h
	rm -f go-auth.so
	rm -f pw
