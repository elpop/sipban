DOCKER ?= docker
TARGET ?= cnsoluciones/sipban

all:
	@echo "Building ${TARGET}"
	$(DOCKER) build -t $(TARGET) -f Dockerfile .