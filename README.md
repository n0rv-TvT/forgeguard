# 🛡️ ForgeGuard

**ForgeGuard** is an open-source DevSecOps Command-Line Interface (CLI) tool written in Go. It statically analyzes GitHub Actions workflow files (`.github/workflows/*.yml`) to detect supply chain vulnerabilities and severe security misconfigurations.

## 🎯 What it Detects (Current Rules)
1. **Unpinned Dependencies:** Action runners relying on moving tags (e.g., `@v3` or `@master`) instead of immutable SHA hashes, which makes the pipeline vulnerable to dependency confusion or maintainer account compromises.
2. **Command Injection Risks:** Untrusted GitHub contexts (like PR titles, issue bodies) being executed directly inside bash `run` blocks.

## 🚀 Getting Started

### Prerequisites
- [Go](https://golang.org/dl/) (1.20 or newer)

### Installation
Clone this repository and compile the binary:
```bash
git clone https://github.com/yourusername/forgeguard.git
cd forgeguard
go mod tidy
go build -o forgeguard main.go
```

### Usage
Run the scanner against a workflow YAML file:
```bash
./forgeguard test-workflow.yml
```

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! 
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License
Distributed under the MIT License. See `LICENSE` for more information.
