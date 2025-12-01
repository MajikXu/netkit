APP_NAME := nk
MAIN_PKG := ./cmd
TARGET_FOLDER := ./target

.PHONY: run
run:
	@echo "Running $(APP_NAME)..."
	@go run $(MAIN_PKG)

.PHONY: build
build:
	@echo "Building $(APP_NAME)..."
	@go build -o $(TARGET_FOLDER)/$(APP_NAME) $(MAIN_PKG)

.PHONY: build-all
build-all: build-windows build-darwin build-linux

.PHONY: build-windows
build-windows:
	@echo "Building $(APP_NAME) for Windows..."
	@GOOS=windows GOARCH=amd64 go build -o $(TARGET_FOLDER)/$(APP_NAME)-windows-amd64.exe $(MAIN_PKG)
	@GOOS=windows GOARCH=arm64 go build -o $(TARGET_FOLDER)/$(APP_NAME)-windows-arm64.exe $(MAIN_PKG)

.PHONY: build-darwin
build-darwin:
	@echo "Building $(APP_NAME) for Darwin..."
	@GOOS=darwin GOARCH=amd64 go build -o $(TARGET_FOLDER)/$(APP_NAME)-darwin-amd64 $(MAIN_PKG)
	@GOOS=darwin GOARCH=arm64 go build -o $(TARGET_FOLDER)/$(APP_NAME)-darwin-arm64 $(MAIN_PKG)

.PHONY: build-linux
build-linux:
	@echo "Building $(APP_NAME) for Linux..."
	@GOOS=linux GOARCH=amd64 go build -o $(TARGET_FOLDER)/$(APP_NAME)-linux-amd64 $(MAIN_PKG)
	@GOOS=linux GOARCH=arm64 go build -o $(TARGET_FOLDER)/$(APP_NAME)-linux-arm64 $(MAIN_PKG)

.PHONY: clean
clean:
	@echo "Cleaning $(TARGET_FOLDER)..."
	@rm -rf $(TARGET_FOLDER)
