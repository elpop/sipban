DOCKER ?= docker
TARGET ?= sipban/sipban:1.0
TARGET_LATEST ?= sipban/sipban:latest

all:
	@echo "Building ${TARGET}"
	$(DOCKER) build -t $(TARGET) -f Dockerfile .

push:
	@echo "Push ${TARGET} and $(TARGET_LATEST)"
	$(DOCKER) push $(TARGET)
	$(DOCKER) tag $(TARGET) $(TARGET_LATEST)
	$(DOCKER) push $(TARGET_LATEST)
