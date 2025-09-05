# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTIDY=$(GOCMD) mod tidy
GORUN=$(GOCMD) run
BINARY_NAME=forwarder

.DEFAULT_GOAL := help

# Targets

all: build

build: tidy
	@echo "Building $(BINARY_NAME)..."
	@$(GOBUILD) -o bin/$(BINARY_NAME) -ldflags="-s -w" .

run: tidy
	@echo "Running the application..."
	@$(GORUN) .

tidy:
	@echo "Tidying dependencies..."
	@$(GOTIDY)

clean:
	@echo "Cleaning..."
	@$(GOCLEAN)
	@rm -f $(BINARY_NAME)

help:
	@echo "Available commands:"
	@echo "  make build    - Build the application for production."
	@echo "  make run      - Run the application for development."
	@echo "  make clean    - Clean build artifacts."
	@echo "  make tidy     - Tidy Go module dependencies."
	@echo "  make help     - Show this help message."

.PHONY: all build run clean tidy help
