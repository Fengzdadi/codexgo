package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoProfileAllowsUnmatchedSimpleCommand(t *testing.T) {
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

	projectPolicy := Policy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Rules:           []Rule{},
	}
	if err := atomicWriteJSON(filepath.Join(cwd, ".codexgo", "policy.json"), projectPolicy); err != nil {
		t.Fatal(err)
	}

	policy, _, err := loadPolicy(cwd)
	if err != nil {
		t.Fatal(err)
	}
	decision := evaluate(policy, "Bash", "npm install lodash")
	if decision.Behavior != "allow" || decision.Source != "go profile" {
		t.Fatalf("expected go profile fallback allow, got %#v", decision)
	}
}

func TestGoProfileAsksSensitiveCommand(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Sources: []PolicySource{
			{Name: "go profile", Policy: goProfilePolicy()},
			{Name: "built-in defaults", Policy: builtInPolicy()},
		},
	}

	decision := evaluate(policy, "Bash", "git push origin main")
	if decision.Behavior != "ask" || decision.RuleName != "ask sensitive go profile commands" {
		t.Fatalf("expected go profile ask for git push, got %#v", decision)
	}
}

func TestGoProfileDeniesDangerousCommand(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Sources: []PolicySource{
			{Name: "go profile", Policy: goProfilePolicy()},
			{Name: "built-in defaults", Policy: builtInPolicy()},
		},
	}

	decision := evaluate(policy, "Bash", "git reset --hard HEAD")
	if decision.Behavior != "deny" || decision.RuleName != "block dangerous go profile commands" {
		t.Fatalf("expected go profile deny for reset hard, got %#v", decision)
	}
}

func TestGoProfileAsksLocalDestructiveCommand(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Sources: []PolicySource{
			{Name: "go profile", Policy: goProfilePolicy()},
			{Name: "built-in defaults", Policy: builtInPolicy()},
		},
	}

	decision := evaluate(policy, "Bash", "rm -rf node_modules")
	if decision.Behavior != "ask" || decision.RuleName != "ask destructive go profile commands" {
		t.Fatalf("expected go profile ask for local destructive command, got %#v", decision)
	}
}

func TestGoProfileAsksComplexUnmatchedCommand(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Sources: []PolicySource{
			{Name: "go profile", Policy: goProfilePolicy()},
			{Name: "built-in defaults", Policy: builtInPolicy()},
		},
	}

	decision := evaluate(policy, "Bash", "npm install lodash && sh setup.sh")
	if decision.Behavior != "ask" {
		t.Fatalf("expected go profile ask for complex shell command, got %#v", decision)
	}
}
