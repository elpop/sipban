DOCKER ?= docker
TARGET ?= sipban/sipban:1.0

all:
	@echo "Building ${TARGET}"
	$(DOCKER) build -t $(TARGET) -f Dockerfile .
