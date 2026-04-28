package codexgo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorShowsInstalledHooksPolicyAndAudit(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cwd := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".codexgo"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	for _, root := range []string{filepath.Join(home, ".codex"), filepath.Join(cwd, ".codex")} {
		if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte("[features]\ncodex_hooks = true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "hooks.json"), []byte(`{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/tmp/codexgo decide"
          }
        ]
      }
    ]
  }
}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := atomicWriteJSON(filepath.Join(cwd, ".codexgo", "policy.json"), Policy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Rules:           []Rule{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".codexgo", "audit.jsonl"), []byte(`{"command":"git status","decision":"allow"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDoctor([]string{"--cwd", cwd}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"CodexGo doctor",
		"Workspace: " + cwd,
		"Overall: OK for this project",
		"Profile: go",
		"Hook: project hook installed",
		"Audit: project audit has entries",
		"user hook",
		"OK hooks enabled",
		"OK PermissionRequest hook installed",
		"project hook",
		"OK effective profile: go",
		"OK loaded policy files:",
		"OK project audit:",
		"last: git status -> allow",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in doctor output:\n%s", want, text)
		}
	}
}

func TestDoctorWarnsForMissingHooksPolicyAndAudit(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cwd := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	var out bytes.Buffer
	if err := runDoctor([]string{"--cwd", cwd}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"Overall: needs setup",
		"Hook: missing",
		"Audit: no entries yet",
		"WARN config missing",
		"WARN hooks missing",
		"Next: codexgo init --scope user",
		"Next: codexgo init --scope project",
		"OK effective profile: manual",
		"WARN no user or project policy files loaded",
		"WARN project audit missing",
		"WARN user audit missing",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in doctor output:\n%s", want, text)
		}
	}
}

func TestDoctorSummaryNotesProjectOnlyHook(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cwd := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(filepath.Join(cwd, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".codexgo"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	if err := os.WriteFile(filepath.Join(cwd, ".codex", "config.toml"), []byte("[features]\ncodex_hooks = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".codex", "hooks.json"), []byte(`{"hooks":{"PermissionRequest":[{"matcher":"Bash","hooks":[{"type":"command","command":"/tmp/codexgo decide"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteJSON(filepath.Join(cwd, ".codexgo", "policy.json"), Policy{DefaultDecision: defaultDecision, Profile: goProfile}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDoctor([]string{"--cwd", cwd}, &out); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		"Overall: OK for this project",
		"Note: user hook is not installed; other projects may not use CodexGo.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected %q in doctor output:\n%s", want, text)
		}
	}
}

func TestIsCodexGoDecideCommand(t *testing.T) {
	for _, command := range []string{
		`"/Users/me/.local/bin/codexgo" decide`,
		`/tmp/codexgo decide`,
		`codexgo decide`,
	} {
		if !isCodexGoDecideCommand(command) {
			t.Fatalf("expected command to match: %s", command)
		}
	}
	for _, command := range []string{
		`codexgo version`,
		`echo decide`,
		`/tmp/other decide`,
	} {
		if isCodexGoDecideCommand(command) {
			t.Fatalf("expected command not to match: %s", command)
		}
	}
}

func TestHasEnabledCodexHooksIgnoresComments(t *testing.T) {
	if hasEnabledCodexHooks("# codex_hooks = true") {
		t.Fatal("expected commented feature flag to be ignored")
	}
	for _, text := range []string{
		"[features]\ncodex_hooks = true\n",
		"[features]\ncodex_hooks=true\n",
		"[features]\ncodex_hooks = true # enabled by CodexGo\n",
	} {
		if !hasEnabledCodexHooks(text) {
			t.Fatalf("expected enabled feature flag to match: %q", text)
		}
	}
}
