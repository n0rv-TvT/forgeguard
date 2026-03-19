.PHONY: all build clean test cross-compile

APP_NAME = forgeguard
BUILD_DIR = build

all: build

build:
	@echo "🔨 Building $(APP_NAME)..."
	@go build -o $(APP_NAME) main.go
	@echo "✅ Build complete!"

clean:
	@echo "🧹 Cleaning up..."
	@rm -rf $(APP_NAME) $(BUILD_DIR)
	@echo "✅ Clean complete!"

test:
	@echo "🧪 Running tests..."
	@go run main.go test-workflow.yml

cross-compile:
	@echo "🌍 Compiling for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 main.go
	@GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 main.go
	@GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 main.go
	@GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe main.go
	@echo "✅ Cross-compilation complete! Check the '$(BUILD_DIR)' directory."
