# 🛡️ ForgeGuard
![Build Status](https://img.shields.io/github/actions/workflow/status/n0rv-TvT/forgeguard/ci.yml?branch=main)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Overview
**ForgeGuard** is an open-source DevSecOps Command-Line Interface (CLI) tool written in Go. It statically analyzes CI/CD pipeline configurations (GitHub Actions and GitLab CI) to detect supply chain vulnerabilities, security misconfigurations, and hardcoded secrets.

**Real-World Use Cases:**
- **Prevent Supply Chain Attacks:** Detect unpinned dependencies or 3rd-party actions that could be compromised via repository hijacking.
- **CI/CD Hardening:** Catch dangerous defaults like `pull_request_target` or overly permissive `GITHUB_TOKEN`s that could lead to repository compromise.
- **Secret Scanning:** Find hardcoded AWS keys, GitHub PATs, and Slack webhooks before they get merged into your main branch.
- **CTF & Bug Bounty:** Useful tool for identifying pipeline vulnerabilities during security assessments.

## Demo

```text
$ forgeguard scan .github/workflows/deploy.yml

  _____                    _____                     _ 
 |  ___|__  _ __ __ _  ___|  __ \ _   _  __ _ _ __  | |
 | |_ / _ \| '__/ _` |/ _ \ |  \/| | | |/ _` | '__| | |
 |  _| (_) | | | (_| |  __/ |__| | |_| | (_| | |    |_|
 |_|  \___/|_|  \__, |\___|_____/ \__,_|\__,_|_|    (_)
                |___/                                  
    CI/CD Supply Chain Security Scanner v1.0.2
    
🔍 Scanning target: .github/workflows/deploy.yml

🛑 Found 3 vulnerabilities in [GitHub CI]: .github/workflows/deploy.yml
------------------------------------------------
1. [CRITICAL] Command Injection Risk
   Step 'Print Issue Title' evaluates untrusted context 'github.event.issue.title' in a shell script.
   Risk: An attacker can submit a malicious payload to execute arbitrary code.
------------------------------------------------
2. [HIGH] Unpinned Action Dependency
   Step 'Checkout code' uses unpinned action 'actions/checkout@v3'.
   Fix: Pin dependencies to a full 40-character commit SHA.
------------------------------------------------
3. [MEDIUM] Missing Job Timeout
   Job 'build' lacks 'timeout-minutes'.
   Risk: If compromised or hung, attackers can run cryptominers on your runner for up to 6 hours.
------------------------------------------------

📊 Scan Complete. Total files: 1 | Total vulnerabilities found: 3
```

## Features
- **Fast Static Analysis:** Parse YAML files locally in milliseconds. No network requests required.
- **Multi-Platform Support:** Analyzes both `.github/workflows/*.yml` and `.gitlab-ci.yml` out of the box.
- **Configurable Output:** Supports colorful terminal output for human consumption, and `JSON` output for pipeline automation.
- **Safe Parsing:** Built-in safeguards against maliciously crafted CI configurations (e.g., file size limits to prevent YAML bombs).
- **No Unsafe Execution:** Analyzes code purely through AST/Regex matching; does not eval or execute untrusted inputs.

## Security Model (Threat Model)

**What ForgeGuard PROTECTS against:**
*   **Pipeline Injection:** Context evaluation vulnerabilities (e.g., untrusted `${{ github.event.issue.title }}` inside `run` blocks).
*   **Dependency Hijacking:** Detection of unpinned dependencies (using moving tags like `@v3` instead of specific SHAs).
*   **Privilege Escalation:** Overly permissive `GITHUB_TOKEN` declarations (`write-all`).
*   **Runner Abuse:** Lack of job timeouts leading to potential cryptomining if the runner is compromised.
*   **Dangerous Triggers:** Catching configurations like `pull_request_target` combined with code checkout.
*   **Secret Leakage:** Simple pattern matching for high-risk tokens (AWS, GitHub, Slack) explicitly placed in YAML.

**What ForgeGuard DOES NOT protect against:**
*   **Runtime Logic Flaws:** ForgeGuard is a *static* analyzer. It does not monitor the actual execution of the pipeline or analyze bash scripts stored in external `.sh` files.
*   **External Vulnerabilities:** It will not find vulnerabilities in the application code itself, only in the CI/CD configuration files.
*   **Sophisticated Obfuscation:** If secrets are split into multiple variables, encoded, or heavily obfuscated, the Regex scanner may miss them.

## Installation

### Prerequisites
- [Go](https://golang.org/dl/) (1.20 or newer)

Clone this repository and compile the binary:
```bash
git clone https://github.com/n0rv-TvT/forgeguard.git
cd forgeguard
go mod tidy
make build
```

## Usage

The CLI uses a command-based structure. 

```bash
# Scan a single file
./forgeguard scan test-workflow.yml

# Scan an entire directory
./forgeguard scan .github/workflows/

# Output as JSON for integration with other DevSecOps tools
./forgeguard scan -output json test-workflow.yml

# Print help menu
./forgeguard help
```

## Limitations
*   Currently primarily focused on GitHub Actions, with expanding coverage for GitLab CI.
*   Deep remote repository scanning is not yet implemented (must run against a cloned local repository).
*   Does not evaluate custom composite actions that are stored in external repositories.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! 
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License
Distributed under the MIT License. See `LICENSE` for more information.
