package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type hooksFile struct {
	Hooks map[string][]hookMatcher `json:"hooks"`
}

type hookMatcher struct {
	Matcher string        `json:"matcher"`
	Hooks   []commandHook `json:"hooks"`
}

type commandHook struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type hookDoctorResult struct {
	Root          string
	ConfigPath    string
	HooksPath     string
	ConfigExists  bool
	HooksExists   bool
	FeatureFlag   bool
	Installed     bool
	HookCommand   string
	ConfigProblem string
	HooksProblem  string
}

type auditDoctorResult struct {
	Path         string
	Exists       bool
	Entries      int
	LastCommand  string
	LastDecision string
	Error        string
}

func runDoctor(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	cwd := fs.String("cwd", "", "project directory to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("doctor does not accept command arguments")
	}
	if *cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		*cwd = wd
	}
	absCWD, err := filepath.Abs(*cwd)
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "CodexGo doctor")
	fmt.Fprintf(out, "Workspace: %s\n\n", absCWD)

	printBinaryDoctor(out)
	printHookDoctor(out, "user", userCodexRoot())
	printHookDoctor(out, "project", filepath.Join(absCWD, ".codex"))
	printPolicyDoctor(out, absCWD)
	printAuditDoctor(out, absCWD)
	return nil
}

func printBinaryDoctor(out io.Writer) {
	fmt.Fprintln(out, "Binary")
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(out, "  WARN current executable: %v\n", err)
	} else if abs, err := filepath.Abs(exe); err == nil {
		fmt.Fprintf(out, "  OK current executable: %s\n", abs)
	} else {
		fmt.Fprintf(out, "  OK current executable: %s\n", exe)
	}

	path, err := exec.LookPath("codexgo")
	if err != nil {
		fmt.Fprintln(out, "  WARN codexgo is not on PATH")
		fmt.Fprintln(out, "       Add ~/.local/bin to PATH or run install.sh again.")
	} else {
		fmt.Fprintf(out, "  OK PATH resolves codexgo: %s\n", path)
	}
	fmt.Fprintln(out)
}

func printHookDoctor(out io.Writer, scope, root string) {
	result := inspectHooks(root)
	fmt.Fprintf(out, "%s hook\n", scope)
	if result.ConfigExists {
		if result.FeatureFlag {
			fmt.Fprintf(out, "  OK hooks enabled: %s\n", result.ConfigPath)
		} else if result.ConfigProblem != "" {
			fmt.Fprintf(out, "  WARN config unreadable: %s (%s)\n", result.ConfigPath, result.ConfigProblem)
		} else {
			fmt.Fprintf(out, "  WARN hooks not enabled in %s\n", result.ConfigPath)
		}
	} else {
		fmt.Fprintf(out, "  WARN config missing: %s\n", result.ConfigPath)
	}

	if result.HooksExists {
		if result.Installed {
			fmt.Fprintf(out, "  OK PermissionRequest hook installed: %s\n", result.HooksPath)
			fmt.Fprintf(out, "     command: %s\n", result.HookCommand)
		} else if result.HooksProblem != "" {
			fmt.Fprintf(out, "  WARN hooks unreadable: %s (%s)\n", result.HooksPath, result.HooksProblem)
		} else {
			fmt.Fprintf(out, "  WARN PermissionRequest codexgo decide hook missing: %s\n", result.HooksPath)
		}
	} else {
		fmt.Fprintf(out, "  WARN hooks missing: %s\n", result.HooksPath)
	}

	if !result.FeatureFlag || !result.Installed {
		fmt.Fprintf(out, "  Next: codexgo init --scope %s\n", scope)
	}
	fmt.Fprintln(out)
}

func printPolicyDoctor(out io.Writer, cwd string) {
	fmt.Fprintln(out, "Policy")
	policy, loaded, err := loadPolicy(cwd)
	if err != nil {
		fmt.Fprintf(out, "  WARN failed to load policy: %v\n\n", err)
		return
	}

	profile := policy.Profile
	source := policy.ProfileSource
	if profile == "" {
		profile = "manual"
		source = "default"
	}
	fmt.Fprintf(out, "  OK effective profile: %s\n", profile)
	fmt.Fprintf(out, "     source: %s\n", source)
	fmt.Fprintf(out, "     default decision: %s\n", policy.DefaultDecision)
	if len(loaded) == 0 {
		fmt.Fprintln(out, "  WARN no user or project policy files loaded")
		fmt.Fprintln(out, "       Run codexgo init --scope user or codexgo init --scope project.")
	} else {
		fmt.Fprintln(out, "  OK loaded policy files:")
		for _, path := range loaded {
			fmt.Fprintf(out, "     - %s\n", path)
		}
	}
	fmt.Fprintln(out)
}

func printAuditDoctor(out io.Writer, cwd string) {
	fmt.Fprintln(out, "Audit")
	results := []auditDoctorResult{
		inspectAudit(filepath.Join(cwd, ".codexgo", "audit.jsonl")),
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		results = append(results, inspectAudit(filepath.Join(home, auditPath)))
	}

	hasEntries := false
	for i, result := range results {
		scope := "project"
		if i == 1 {
			scope = "user"
		}
		if result.Error != "" {
			fmt.Fprintf(out, "  WARN %s audit unreadable: %s (%s)\n", scope, result.Path, result.Error)
			continue
		}
		if !result.Exists {
			fmt.Fprintf(out, "  WARN %s audit missing: %s\n", scope, result.Path)
			continue
		}
		if result.Entries == 0 {
			fmt.Fprintf(out, "  WARN %s audit has no entries: %s\n", scope, result.Path)
			continue
		}
		hasEntries = true
		fmt.Fprintf(out, "  OK %s audit: %s (%d entries)\n", scope, result.Path, result.Entries)
		if result.LastCommand != "" {
			fmt.Fprintf(out, "     last: %s", result.LastCommand)
			if result.LastDecision != "" {
				fmt.Fprintf(out, " -> %s", result.LastDecision)
			}
			fmt.Fprintln(out)
		}
	}
	if !hasEntries {
		fmt.Fprintln(out, "  Next: start a new Codex session and run a command that requests permission.")
	}
	fmt.Fprintln(out)
}

func userCodexRoot() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return filepath.Join(".codex")
	}
	return filepath.Join(home, ".codex")
}

func inspectHooks(root string) hookDoctorResult {
	result := hookDoctorResult{
		Root:       root,
		ConfigPath: filepath.Join(root, "config.toml"),
		HooksPath:  filepath.Join(root, "hooks.json"),
	}

	config, err := os.ReadFile(result.ConfigPath)
	if os.IsNotExist(err) {
		result.ConfigExists = false
	} else if err != nil {
		result.ConfigExists = true
		result.ConfigProblem = err.Error()
	} else {
		result.ConfigExists = true
		result.FeatureFlag = hasEnabledCodexHooks(string(config))
	}

	data, err := os.ReadFile(result.HooksPath)
	if os.IsNotExist(err) {
		result.HooksExists = false
		return result
	}
	if err != nil {
		result.HooksExists = true
		result.HooksProblem = err.Error()
		return result
	}
	result.HooksExists = true

	var hooks hooksFile
	if err := json.Unmarshal(data, &hooks); err != nil {
		result.HooksProblem = err.Error()
		return result
	}
	for _, matcher := range hooks.Hooks["PermissionRequest"] {
		for _, hook := range matcher.Hooks {
			if hook.Type != "" && hook.Type != "command" {
				continue
			}
			if isCodexGoDecideCommand(hook.Command) {
				result.Installed = true
				result.HookCommand = hook.Command
				return result
			}
		}
	}
	return result
}

func isCodexGoDecideCommand(command string) bool {
	fields := strings.Fields(command)
	hasDecide := false
	hasCodexGo := false
	for _, field := range fields {
		clean := strings.Trim(field, `"'`)
		if clean == "decide" {
			hasDecide = true
		}
		if strings.Contains(filepath.Base(clean), "codexgo") {
			hasCodexGo = true
		}
	}
	return hasCodexGo && hasDecide
}

func inspectAudit(path string) auditDoctorResult {
	result := auditDoctorResult{Path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return result
	}
	if err != nil {
		result.Exists = true
		result.Error = err.Error()
		return result
	}
	result.Exists = true

	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		result.Entries++
		var entry AuditEntry
		if err := json.Unmarshal(trimmed, &entry); err == nil {
			result.LastCommand = entry.Command
			result.LastDecision = entry.Decision
		}
	}
	return result
}
