package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSuggestGroupsAskEntries(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd,
		`{"command":"git commit -m test","decision":"ask"}`,
		`{"command":"git commit -m docs","decision":"ask"}`,
		`{"command":"git push origin main","decision":"ask"}`,
		`{"command":"rm -rf /","decision":"ask"}`,
		`{"command":"npm test","decision":"allow"}`,
	)

	var out bytes.Buffer
	if err := runSuggest([]string{"--limit", "0", "--scope", "project"}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"git commit",
		"seen: 2",
		"suggestion: allow prefix",
		"codexgo allow --scope project --match prefix 'git commit'",
		"git push",
		"suggestion: ask prefix",
		"codexgo ask --scope project --match prefix 'git push'",
		"rm -rf /",
		"suggestion: deny exact",
		"codexgo deny --scope project --match exact 'rm -rf /'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in suggest output:\n%s", want, text)
		}
	}
	if strings.Contains(text, "npm test") {
		t.Fatalf("expected non-ask audit entries to be ignored:\n%s", text)
	}
}

func TestSuggestLimitAppliesRecentEntries(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd,
		`{"command":"git add README.md","decision":"ask"}`,
		`{"command":"git commit -m test","decision":"ask"}`,
		`{"command":"git push origin main","decision":"ask"}`,
	)

	var out bytes.Buffer
	if err := runSuggest([]string{"--audit-limit", "2"}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	if strings.Contains(text, "git add") {
		t.Fatalf("expected limit to exclude oldest audit entry:\n%s", text)
	}
	for _, want := range []string{"git commit", "git push"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in limited suggest output:\n%s", want, text)
		}
	}
}

func TestSuggestLimitAppliesOutputCount(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd,
		`{"command":"git add README.md","decision":"ask"}`,
		`{"command":"git commit -m test","decision":"ask"}`,
		`{"command":"git push origin main","decision":"ask"}`,
	)

	var out bytes.Buffer
	if err := runSuggest([]string{"--limit", "2", "--audit-limit", "0"}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	if !strings.Contains(text, "showing: 2/3") {
		t.Fatalf("expected output count in suggest header:\n%s", text)
	}
	if strings.Contains(text, "git push") {
		t.Fatalf("expected output limit to truncate third suggestion:\n%s", text)
	}
}

func TestSuggestSplitsCompoundCommands(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd, `{"command":"git add README.md && git commit -m test && git push origin main","decision":"ask"}`)

	var out bytes.Buffer
	if err := runSuggest([]string{"--limit", "0"}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"codexgo allow --scope project --match prefix 'git add'",
		"codexgo allow --scope project --match prefix 'git commit'",
		"codexgo ask --scope project --match prefix 'git push'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in compound suggest output:\n%s", want, text)
		}
	}
	if strings.Contains(text, "git add README.md && git commit") {
		t.Fatalf("expected compound command to be split into segments:\n%s", text)
	}
}

func TestSuggestForcePushUsesSpecificDeny(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd, `{"command":"git tag -fa v0.1.3 && git push --force origin v0.1.3","decision":"ask"}`)

	var out bytes.Buffer
	if err := runSuggest([]string{"--limit", "0"}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"git push --force",
		"suggestion: deny prefix",
		"codexgo deny --scope project --match prefix 'git push --force'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in force-push suggest output:\n%s", want, text)
		}
	}
	if strings.Contains(text, "codexgo deny --scope project --match prefix 'git push'") {
		t.Fatalf("expected force push deny to avoid broad git push pattern:\n%s", text)
	}
}

func TestSuggestNoAskEntries(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd, `{"command":"git status","decision":"allow"}`)

	var out bytes.Buffer
	if err := runSuggest(nil, &out); err != nil {
		t.Fatal(err)
	}

	if got := strings.TrimSpace(out.String()); got != "No ask entries found in recent audit logs." {
		t.Fatalf("unexpected empty suggest output: %q", got)
	}
}

func TestSuggestReadOnlyNetworkPipeUsesExactAllow(t *testing.T) {
	cwd := suggestTestCWD(t)
	writeSuggestAudit(t, cwd, `{"command":"curl https://api.github.com/repos/fengzdadi/codexgo|rg tag_name","decision":"ask"}`)

	var out bytes.Buffer
	if err := runSuggest([]string{"--limit", "0"}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"suggestion: allow exact",
		"codexgo allow --scope project --match exact 'curl https://api.github.com/repos/fengzdadi/codexgo|rg tag_name'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in suggest output:\n%s", want, text)
		}
	}
}

func suggestTestCWD(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cwd := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".codexgo"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previous)
	})
	return cwd
}

func writeSuggestAudit(t *testing.T, cwd string, lines ...string) {
	t.Helper()
	var data strings.Builder
	for _, line := range lines {
		data.WriteString(fmt.Sprintf("%s\n", line))
	}
	if err := os.WriteFile(filepath.Join(cwd, ".codexgo", "audit.jsonl"), []byte(data.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
