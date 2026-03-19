package scanner

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Issue represents a detected vulnerability
type Issue struct {
	Rule    string
	Message string
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
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
}

// Helper to check for overly permissive tokens
func checkPermissions(perms interface{}, scope string) []Issue {
	var issues []Issue
	
	if pStr, ok := perms.(string); ok {
		if pStr == "write-all" {
			issues = append(issues, Issue{
				Rule:    "Overly Permissive Tokens",
				Message: scope + " has 'permissions: write-all'.\n   Risk: Compromised runner can overwrite code, releases, and packages.\n   Fix: Use principle of least privilege (e.g., 'contents: read').",
			})
		}
	} else if pMap, ok := perms.(map[string]interface{}); ok {
		for k, v := range pMap {
			if v == "write" && (k == "contents" || k == "packages" || k == "security-events" || k == "actions") {
				issues = append(issues, Issue{
					Rule:    "Dangerous Token Permission",
					Message: scope + " has 'permissions: " + k + ": write'.\n   Risk: Grants write access to critical repository components.\n   Fix: Ensure this workflow strictly requires write access.",
				})
			}
		}
	}
	return issues
}

// ScanFile parses the YAML and applies security rules
func ScanFile(filepath string) ([]Issue, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var workflow Workflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return nil, err
	}

	var issues []Issue

	// Rule 3: Global Permissions Check
	if workflow.Permissions != nil {
		issues = append(issues, checkPermissions(workflow.Permissions, "Global workflow")...)
	}

	// Rule 5: Dangerous pull_request_target trigger
	onBytes, _ := yaml.Marshal(workflow.On)
	if strings.Contains(string(onBytes), "pull_request_target") {
		issues = append(issues, Issue{
			Rule:    "Dangerous Trigger (pull_request_target)",
			Message: "Workflow triggers on 'pull_request_target'.\n   Risk: Runs with elevated privileges and secret access. If you checkout untrusted PR code, attackers can steal secrets.\n   Fix: Require approval for external contributors or use 'pull_request' instead.",
		})
	}

	curlBashRegex := regexp.MustCompile(`(?i)(curl|wget).*\|\s*(bash|sh)`)

	for jobName, job := range workflow.Jobs {
		// Rule 3b: Job-level Permissions Check
		if job.Permissions != nil {
			issues = append(issues, checkPermissions(job.Permissions, "Job '"+jobName+"'")...)
		}

		// Rule 6: Missing timeout-minutes (Cryptomining protection)
		if job.TimeoutMinutes == 0 {
			issues = append(issues, Issue{
				Rule:    "Missing Job Timeout",
				Message: "Job '" + jobName + "' lacks 'timeout-minutes'.\n   Risk: If compromised or hung, attackers can run cryptominers on your runner for up to 6 hours.\n   Fix: Add 'timeout-minutes: 15' (or appropriate limit).",
			})
		}

		for _, step := range job.Steps {
			// Rule 1: Unpinned Dependency
			if step.Uses != "" {
				if strings.Contains(step.Uses, "@") {
					parts := strings.Split(step.Uses, "@")
					if len(parts) == 2 {
						version := parts[1]
						matched, _ := regexp.MatchString(`^[a-fA-F0-9]{40}$`, version)
						if !matched {
							issues = append(issues, Issue{
								Rule:    "Unpinned Action Dependency",
								Message: "Step '" + step.Name + "' uses unpinned action '" + step.Uses + "'.\n   Risk: If the action owner is compromised, malicious code can be injected into your build.\n   Fix: Pin dependencies to a full 40-character commit SHA.",
							})
						}
					}
				}
			}

			if step.Run != "" {
				// Rule 2: Potential Command Injection via Context Variables
				untrustedContexts := []string{
					"github.event.issue.title",
					"github.event.issue.body",
					"github.event.pull_request.title",
					"github.event.pull_request.body",
					"github.event.comment.body",
					"github.head_ref",
				}
				for _, ctx := range untrustedContexts {
					if strings.Contains(step.Run, "${{") && strings.Contains(step.Run, ctx) {
						issues = append(issues, Issue{
							Rule:    "Command Injection Risk",
							Message: "Step '" + step.Name + "' evaluates untrusted context '" + ctx + "' in a shell script.\n   Risk: An attacker can submit a malicious payload to execute arbitrary code.\n   Fix: Pass the context via environment variables instead.",
						})
						break 
					}
				}

				// Rule 4: Dangerous Curl to Bash
				if curlBashRegex.MatchString(step.Run) {
					issues = append(issues, Issue{
						Rule:    "Remote Code Execution (Curl to Bash)",
						Message: "Step '" + step.Name + "' downloads and executes a script directly via pipe.\n   Risk: If the remote server is compromised or MITM'd, you will execute malware.\n   Fix: Download the script, verify its SHA256 checksum, then execute it.",
					})
				}

				// Rule 7: Deprecated set-env / add-path commands
				if strings.Contains(step.Run, "::set-env") || strings.Contains(step.Run, "::add-path") {
					issues = append(issues, Issue{
						Rule:    "Deprecated Runner Commands",
						Message: "Step '" + step.Name + "' uses deprecated 'set-env' or 'add-path'.\n   Risk: These commands are vulnerable to stdout command injection.\n   Fix: Write to $GITHUB_ENV or $GITHUB_PATH instead.",
					})
				}
			}
		}
	}

	return issues, nil
}
