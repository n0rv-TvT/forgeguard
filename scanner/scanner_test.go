package scanner

import (
	"testing"
)

func TestScanData(t *testing.T) {
	tests := []struct {
		name          string
		yamlData      string
		expectedRules []string
		mustNotHave   []string
		expectError   bool
	}{
		{
			name: "Command Injection Risk",
			yamlData: `
name: Test
on: push
jobs:
  test:
    timeout-minutes: 10
    steps:
      - name: Inject
        run: echo "${{ github.event.issue.title }}"
`,
			expectedRules: []string{"Command Injection Risk"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Unpinned Dependency",
			yamlData: `
name: Test
on: push
jobs:
  test:
    timeout-minutes: 10
    steps:
      - name: Checkout
        uses: actions/checkout@v3
`,
			expectedRules: []string{"Unpinned Action Dependency"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Secure Workflow",
			yamlData: `
name: Secure
on: push
permissions:
  contents: read
jobs:
  test:
    timeout-minutes: 10
    steps:
      - name: Checkout
        uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - name: Safe run
        run: echo "Hello World"
`,
			expectedRules: []string{},
			mustNotHave:   []string{"Command Injection Risk", "Unpinned Action Dependency", "Missing Job Timeout", "Overly Permissive GITHUB_TOKEN"},
			expectError:   false,
		},
		{
			name: "Workflow Run Trigger",
			yamlData: `
name: Target Workflow
on:
  workflow_run:
    workflows: ["Untrusted Workflow"]
    types: [completed]
jobs:
  test:
    steps:
      - run: echo "Hello"
      - uses: actions/download-artifact@v3
`,
			expectedRules: []string{"Dangerous Trigger (workflow_run) with Artifact Download"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Github Env Injection",
			yamlData: `
name: Env Inject
on: push
jobs:
  test:
    steps:
      - name: Inject
        run: echo "VAR=${{ github.event.issue.title }}" >> $GITHUB_ENV
`,
			expectedRules: []string{"Environment File Injection", "Command Injection Risk"},
			mustNotHave:   []string{},
			expectError:   false,
		},
		{
			name: "Github Script Injection",
			yamlData: `
name: Script Inject
on: push
jobs:
  test:
    steps:
      - name: Inject
        uses: actions/github-script@v6
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
`,
			expectedRules: []string{"GitHub Script Injection"},
			mustNotHave:   []string{},
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues, err := ScanData([]byte(tt.yamlData))

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
