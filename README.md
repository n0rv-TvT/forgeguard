# 🛡️ ForgeGuard
![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/forgeguard/ci.yml?branch=main)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**ForgeGuard** is an open-source DevSecOps Command-Line Interface (CLI) tool written in Go. It statically analyzes GitHub Actions workflow files (`.github/workflows/*.yml`) to detect supply chain vulnerabilities, misconfigurations, and hardcoded secrets.

## 🎯 What it Detects (Current Rules)
1. **Unpinned Dependencies:** Action runners relying on moving tags (e.g., `@v3` or `@master`) instead of immutable SHA hashes.
2. **Command Injection Risks:** Untrusted GitHub contexts (like PR titles) executed directly inside bash `run` blocks.
3. **Overly Permissive Tokens:** Global or job-level `write-all` or `contents: write` permissions.
4. **Remote Code Execution:** Inline scripts using `curl | bash` without checksum verification.
5. **Dangerous Triggers:** Workflows utilizing `pull_request_target` which can lead to repository compromise.
6. **Missing Timeouts:** Jobs lacking `timeout-minutes`, mitigating risk of cryptomining abuse.
7. **Deprecated Commands:** Use of legacy commands like `::set-env` that allow standard out injection.
8. **Hardcoded Secrets:** Detection of hardcoded AWS Access Keys (`AKIA...`) and other tokens/passwords directly in the workflow files.

## 🚀 Getting Started

### Prerequisites
- [Go](https://golang.org/dl/) (1.20 or newer)

### Installation
Clone this repository and compile the binary:
```bash
git clone https://github.com/yourusername/forgeguard.git
cd forgeguard
go mod tidy
make build
```

### Usage
Run the scanner against a single workflow YAML file or an entire directory:
```bash
# Scan a single file
./forgeguard test-workflow.yml

# Scan an entire directory
./forgeguard .github/workflows/

# Output as JSON for integration with other tools
./forgeguard --output json test-workflow.yml
```

### Cross-Compilation (Releases)
You can easily compile ForgeGuard for Linux, Windows, and macOS using the included Makefile:
```bash
make cross-compile
```
*(Binaries will be output to the `build/` directory).*

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! 
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License
Distributed under the MIT License. See `LICENSE` for more information.
