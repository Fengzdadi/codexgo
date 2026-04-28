package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	scope := fs.String("scope", "user", "installation scope: user or project")
	bin := fs.String("bin", "", "absolute path to codexgo binary")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		*bin = exe
	}

	var root string
	switch *scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		root = filepath.Join(home, ".codex")
	case "project":
		root = ".codex"
	default:
		return fmt.Errorf("invalid scope %q", *scope)
	}

	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if err := ensureFeatureFlag(filepath.Join(root, "config.toml")); err != nil {
		return err
	}
	if err := writeHooks(filepath.Join(root, "hooks.json"), *bin); err != nil {
		return err
	}

	policyDir := ".codexgo"
	if *scope == "user" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		policyDir = filepath.Join(home, ".codexgo")
	}
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		return err
	}
	policyFile := filepath.Join(policyDir, "policy.json")
	if _, err := os.Stat(policyFile); os.IsNotExist(err) {
		if err := atomicWriteJSON(policyFile, emptyPolicy()); err != nil {
			return err
		}
	}

	fmt.Printf("Installed CodexGo %s hook in %s\n", *scope, root)
	fmt.Printf("Policy: %s\n", policyFile)
	return nil
}

func ensureFeatureFlag(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return os.WriteFile(path, []byte("[features]\ncodex_hooks = true\n"), 0o644)
	}
	if err != nil {
		return err
	}
	text := string(data)
	if strings.Contains(text, "codex_hooks = true") {
		return nil
	}
	appendText := "\n[features]\ncodex_hooks = true\n"
	if strings.Contains(text, "[features]") {
		appendText = "\n# CodexGo requires hooks to be enabled.\n# If another [features] table already exists above, move this key there.\n# codex_hooks = true\n"
	}
	return os.WriteFile(path, append(data, []byte(appendText)...), 0o644)
}

func writeHooks(path, bin string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; add codexgo manually to avoid overwriting existing hooks", path)
	} else if !os.IsNotExist(err) {
		return err
	}

	hooks := map[string]any{
		"hooks": map[string]any{
			"PermissionRequest": []map[string]any{
				{
					"matcher": "Bash",
					"hooks": []map[string]any{
						{
							"type":          "command",
							"command":       fmt.Sprintf("%q decide", bin),
							"timeout":       5,
							"statusMessage": "Checking CodexGo policy",
						},
					},
				},
			},
		},
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	return writeJSON(file, hooks)
}
