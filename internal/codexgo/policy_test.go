package codexgo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyUsesBuiltInDefaultsWithoutPolicyFiles(t *testing.T) {
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

	policy, loaded, err := loadPolicy(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected no loaded policy files, got %#v", loaded)
	}
	decision := evaluate(policy, "Bash", "git status")
	if decision.Behavior != "allow" {
		t.Fatalf("expected built-in allow, got %#v", decision)
	}
}

func TestLoadPolicyMergesExternalRulesOntoBuiltIns(t *testing.T) {
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
		Rules: []Rule{
			{
				Name:     "project allow commit",
				Decision: "allow",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{"git commit"},
			},
		},
	}
	if err := atomicWriteJSON(filepath.Join(cwd, ".codexgo", "policy.json"), projectPolicy); err != nil {
		t.Fatal(err)
	}

	policy, loaded, err := loadPolicy(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected one loaded policy file, got %#v", loaded)
	}
	if decision := evaluate(policy, "Bash", "git status"); decision.Behavior != "allow" {
		t.Fatalf("expected built-in git status allow, got %#v", decision)
	}
	if decision := evaluate(policy, "Bash", "git commit -m test"); decision.Behavior != "allow" {
		t.Fatalf("expected project git commit allow, got %#v", decision)
	}
}

func TestLoadPolicySourcePriority(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cwd := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(filepath.Join(home, ".codexgo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".codexgo"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	userPolicy := Policy{
		DefaultDecision: defaultDecision,
		Rules: []Rule{
			{
				Name:     "user ask push",
				Decision: "ask",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{"git push"},
			},
		},
	}
	projectPolicy := Policy{
		DefaultDecision: defaultDecision,
		Rules: []Rule{
			{
				Name:     "project allow push",
				Decision: "allow",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{"git push"},
			},
		},
	}
	if err := atomicWriteJSON(filepath.Join(home, ".codexgo", "policy.json"), userPolicy); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteJSON(filepath.Join(cwd, ".codexgo", "policy.json"), projectPolicy); err != nil {
		t.Fatal(err)
	}

	policy, _, err := loadPolicy(cwd)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, source := range policy.Sources {
		got = append(got, source.Name)
	}
	want := []string{"project policy", "user policy", "built-in defaults"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected source order: got %#v want %#v", got, want)
	}

	decision := evaluate(policy, "Bash", "git push")
	if decision.Behavior != "allow" || decision.Source != "project policy" {
		t.Fatalf("expected project allow to win, got %#v", decision)
	}
}
