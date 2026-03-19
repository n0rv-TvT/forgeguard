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
	Message  string `json:"message"`
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
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
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
				Message:  scope + " has 'permissions: write-all'.\n   Risk: Compromised runner can overwrite code, releases, and packages.\n   Fix: Use principle of least privilege (e.g., 'contents: read').",
			})
		}
	} else if pMap, ok := perms.(map[string]interface{}); ok {
		for k, v := range pMap {
			if v == "write" && (k == "contents" || k == "packages" || k == "security-events" || k == "actions") {
				issues = append(issues, Issue{
					Rule:     "Dangerous Token Permission",
					Severity: "HIGH",
					Message:  scope + " has 'permissions: " + k + ": write'.\n   Risk: Grants write access to critical repository components.\n   Fix: Ensure this workflow strictly requires write access.",
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
			Message:  "Found a hardcoded AWS Access Key (AKIA...) in the workflow file.\n   Risk: Anyone who can read this repo can compromise your AWS environment.\n   Fix: Move this to GitHub Secrets.",
		})
	}
	if githubPatRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded GitHub Token",
			Severity: "CRITICAL",
			Message:  "Found a hardcoded GitHub Personal Access Token in the workflow file.\n   Risk: Full repository or org compromise.\n   Fix: Move this to GitHub Secrets.",
		})
	}
	if slackWebhookRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Hardcoded Slack Webhook",
			Severity: "MEDIUM",
			Message:  "Found a hardcoded Slack webhook.\n   Risk: Attackers can spam or phish your internal channels.\n   Fix: Move this to GitHub Secrets.",
		})
	}
	if genericSecretRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Potential Hardcoded Secret",
			Severity: "HIGH",
			Message:  "Found a potential hardcoded password/token/secret in the workflow file.\n   Risk: Hardcoding secrets leads to credential theft.\n   Fix: Move this to GitHub Secrets.",
		})
	}

	nodeRegex := regexp.MustCompile(`(?i)setup-node@v[123]\b`)
	if nodeRegex.MatchString(contentStr) {
		issues = append(issues, Issue{
			Rule:     "Deprecated Action Environment (Node.js)",
			Severity: "MEDIUM",
			Message:  "Found usage of deprecated setup-node versions.\n   Risk: Older Node.js versions have unpatched vulnerabilities.\n   Fix: Upgrade to setup-node@v4 or newer.",
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
			Message:  "Workflow triggers on 'pull_request_target'.\n   Risk: Runs with elevated privileges and secret access. If you checkout untrusted PR code, attackers can steal secrets.",
		})
	}
	if strings.Contains(onString, "workflow_run") {
		issues = append(issues, Issue{
			Rule:     "Dangerous Trigger (workflow_run)",
			Severity: "HIGH",
			Message:  "Workflow triggers on 'workflow_run'.\n   Risk: Can be exploited similarly to pull_request_target if evaluating artifacts from untrusted runs.",
		})
	}

	curlBashRegex := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh)`)

	for jobName, job := range workflow.Jobs {
		if job.Permissions != nil {
			issues = append(issues, checkPermissions(job.Permissions, "Job '"+jobName+"'")...)
		}

		if job.TimeoutMinutes == 0 {
			issues = append(issues, Issue{
				Rule:     "Missing Job Timeout",
				Severity: "MEDIUM",
				Message:  "Job '" + jobName + "' lacks 'timeout-minutes'.\n   Risk: If compromised or hung, attackers can run cryptominers on your runner for up to 6 hours.",
			})
		}

		for _, step := range job.Steps {
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
								Message:  "Step '" + step.Name + "' uses unpinned action '" + step.Uses + "'.\n   Fix: Pin dependencies to a full 40-character commit SHA.",
							})
						}
					}
				}
				
				if !strings.HasPrefix(step.Uses, "actions/") && !strings.HasPrefix(step.Uses, "github/") && !strings.HasPrefix(step.Uses, "aws-actions/") && !strings.HasPrefix(step.Uses, "azure/") {
					issues = append(issues, Issue{
						Rule:     "Unverified 3rd-Party Action",
						Severity: "LOW",
						Message:  "Step '" + step.Name + "' uses '" + step.Uses + "' which is not a highly-trusted organization.",
					})
				}

				if strings.Contains(step.Uses, "actions/github-script") {
					if scriptInter, ok := step.With["script"]; ok {
						scriptStr := fmt.Sprintf("%v", scriptInter)
						if strings.Contains(scriptStr, "${{") && (strings.Contains(scriptStr, "github.event.issue") || strings.Contains(scriptStr, "github.event.pull_request")) {
							issues = append(issues, Issue{
								Rule:     "GitHub Script Injection",
								Severity: "CRITICAL",
								Message:  "Step '" + step.Name + "' passes untrusted context into github-script.\n   Risk: Can lead to JavaScript execution on the runner.",
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
							Message:  "Step '" + step.Name + "' evaluates untrusted context '" + ctx + "' in a shell script.\n   Risk: An attacker can submit a malicious payload to execute arbitrary code.",
						})
						break
					}
				}

				if curlBashRegex.MatchString(step.Run) {
					issues = append(issues, Issue{
						Rule:     "Remote Code Execution (Curl to Bash)",
						Severity: "HIGH",
						Message:  "Step '" + step.Name + "' downloads and executes a script directly via pipe.",
					})
				}

				if strings.Contains(step.Run, "::set-env") || strings.Contains(step.Run, "::add-path") {
					issues = append(issues, Issue{
						Rule:     "Deprecated Runner Commands",
						Severity: "HIGH",
						Message:  "Step '" + step.Name + "' uses deprecated 'set-env' or 'add-path'.",
					})
				}

				envInjectRegex := regexp.MustCompile(`echo\s+['"]?.*?\$\{?.*?\}?.*?['"]?\s*>>\s*\$GITHUB_ENV`)
				if envInjectRegex.MatchString(step.Run) && strings.Contains(step.Run, "${{") {
					issues = append(issues, Issue{
						Rule:     "Environment File Injection",
						Severity: "HIGH",
						Message:  "Step '" + step.Name + "' injects potentially untrusted context into $GITHUB_ENV.\n   Risk: If an attacker can inject newlines, they can override critical env vars.",
					})
				}
			}
		}
	}

	return issues, nil
}
