package scanner

import (
	"testing"
)

func TestScanGitlabData(t *testing.T) {
	tests := []struct {
		name          string
		yamlData      string
		expectedRules []string
		mustNotHave   []string
		expectError   bool
	}{
		{
			name: "Command Injection Risk via MR Title",
			yamlData: `
build:
  script:
    - echo "Building project"
    - echo "MR Title: $CI_MERGE_REQUEST_TITLE"
`,
			expectedRules: []string{"Command Injection Risk"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Remote Code Execution via Curl",
			yamlData: `
deploy:
  script:
    - curl -s https://example.com/install.sh | bash
`,
			expectedRules: []string{"Remote Code Execution (Curl to Bash)"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Unpinned Docker Image",
			yamlData: `
test:
  image: golang:latest
  script:
    - go test ./...
`,
			expectedRules: []string{"Unpinned Docker Image"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Secure GitLab CI",
			yamlData: `
variables:
  GO_VERSION: "1.20"

stages:
  - build
  - test

build:
  stage: build
  image: golang@sha256:d9b23b1238479bb3d8c1c49b389ab4eb6d0291400d358655c6baad26279f6681
  script:
    - go build -o myapp .
`,
			expectedRules: []string{},
			mustNotHave:   []string{"Command Injection Risk", "Remote Code Execution (Curl to Bash)", "Unpinned Docker Image"},
			expectError:   false,
		},
		{
			name: "Hardcoded Secret",
			yamlData: `
deploy:
  script:
    - export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
    - deploy.sh
`,
			expectedRules: []string{"Hardcoded AWS Key"},
			mustNotHave:   []string{},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := ScanGitlabData([]byte(tt.yamlData))

			if (err != nil) != tt.expectError {
				t.Fatalf("Expected error: %v, got: %v", tt.expectError, err)
			}

			foundRules := make(map[string]bool)
			for _, issue := range issues {
				foundRules[issue.Rule] = true
			}

			// Check expected rules are present
			for _, rule := range tt.expectedRules {
				if !foundRules[rule] {
					t.Errorf("Expected to find rule '%s', but didn't", rule)
				}
			}

			// Check must not have rules are absent
			for _, rule := range tt.mustNotHave {
				if foundRules[rule] {
					t.Errorf("Expected NOT to find rule '%s', but did", rule)
				}
			}
		})
	}
}
