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
	Name string         `yaml:"name"`
	Jobs map[string]Job `yaml:"jobs"`
}

type Job struct {
	Steps []Step `yaml:"steps"`
}

type Step struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
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

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			// Rule 1: Unpinned Dependency
			// Checks if an action uses a branch/tag instead of a strict SHA commit hash
			if step.Uses != "" {
				if strings.Contains(step.Uses, "@") {
					parts := strings.Split(step.Uses, "@")
					if len(parts) == 2 {
						version := parts[1]
						// A full Git SHA-1 hash is exactly 40 hex characters
						matched, _ := regexp.MatchString(`^[a-fA-F0-9]{40}$`, version)
						if !matched {
							issues = append(issues, Issue{
								Rule:    "Unpinned Action Dependency",
								Message: "Job '" + jobName + "' uses unpinned action '" + step.Uses + "'.\n   Risk: If the action owner is compromised, malicious code can be injected into your build.\n   Fix: Pin dependencies to a full 40-character commit SHA.",
							})
						}
					}
				}
			}

			// Rule 2: Potential Command Injection via Context Variables
			// Untrusted variables like issue titles or PR titles shouldn't be executed directly in bash
			if step.Run != "" {
				untrustedContexts := []string{
					"github.event.issue.title",
					"github.event.issue.body",
					"github.event.pull_request.title",
					"github.event.pull_request.body",
					"github.head_ref",
				}
				
				for _, ctx := range untrustedContexts {
					if strings.Contains(step.Run, "${{") && strings.Contains(step.Run, ctx) {
						issues = append(issues, Issue{
							Rule:    "Command Injection Risk",
							Message: "Job '" + jobName + "' directly evaluates untrusted context '" + ctx + "' in a shell script.\n   Risk: An attacker can submit a malicious PR title to execute arbitrary code on your runner.\n   Fix: Pass the context via environment variables instead.",
						})
						break // Only report once per run block to avoid spam
					}
				}
			}
		}
	}

	return issues, nil
}
