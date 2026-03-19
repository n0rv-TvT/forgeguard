.PHONY: all build clean test cross-compile

APP_NAME = forgeguard
BUILD_DIR = build
VERSION ?= 1.0.2

all: build

build:
	@echo "🔨 Building $(APP_NAME)..."
	@go build -ldflags "-X main.Version=$(VERSION)" -o $(APP_NAME) .
	@echo "✅ Build complete!"

clean:
	@echo "🧹 Cleaning up..."
	@rm -rf $(APP_NAME) $(BUILD_DIR)
	@echo "✅ Clean complete!"

test:
	@echo "🧪 Running tests..."
	@go test -v ./...

cross-compile:
	@echo "🌍 Compiling for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 .
	@GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 .
	@GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe .
	@echo "✅ Cross-compilation complete! Check the '$(BUILD_DIR)' directory."
