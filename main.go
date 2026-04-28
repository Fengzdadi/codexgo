package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	version         = "v0.1.1"
	defaultDecision = "ask"
	userPolicyPath  = ".codexgo/policy.json"
	auditPath       = ".codexgo/audit.jsonl"
)

type HookInput struct {
	SessionID     string          `json:"session_id"`
	CWD           string          `json:"cwd"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

type ToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type Policy struct {
	DefaultDecision string `json:"defaultDecision"`
	Rules           []Rule `json:"rules"`
}

type Rule struct {
	Name     string   `json:"name"`
	Decision string   `json:"decision"`
	Tools    []string `json:"tools"`
	Match    string   `json:"match"`
	Commands []string `json:"commands"`
}

type ResolvedPolicy struct {
	DefaultDecision string
	Sources         []PolicySource
}

type PolicySource struct {
	Name   string
	Path   string
	Policy Policy
}

type Decision struct {
	Behavior string
	Source   string
	RuleName string
	Match    string
	Pattern  string
	Reason   string
}

type HookOutput struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

type HookSpecificOutput struct {
	HookEventName string             `json:"hookEventName"`
	Decision      HookDecisionOutput `json:"decision"`
}

type HookDecisionOutput struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "decide":
		err = runDecide(os.Stdin, os.Stdout)
	case "init":
		err = runInit(os.Args[2:])
	case "allow", "deny", "ask":
		err = runPolicyCommand(os.Args[1], os.Args[2:], os.Stdout)
	case "remove":
		err = runRemoveCommand(os.Args[2:], os.Stdout)
	case "explain":
		err = runExplain(os.Args[2:], os.Stdout)
	case "list":
		err = runList(os.Args[2:], os.Stdout)
	case "sample-policy":
		err = writeJSON(os.Stdout, samplePolicy())
	case "audit":
		err = runAudit()
	case "version":
		fmt.Fprintf(os.Stdout, "CodexGo %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "codexgo:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `codexgo manages Codex PermissionRequest approvals.

Usage:
  codexgo init [--scope user|project] [--bin /path/to/codexgo]
  codexgo allow [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo deny  [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo ask   [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo remove [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo explain [--cwd /path/to/project] [--tool Bash] <command>
  codexgo list [--cwd /path/to/project]
  codexgo decide
  codexgo sample-policy
  codexgo audit
  codexgo version`)
}

func runDecide(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return errors.New("empty hook input")
	}

	var input HookInput
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("decode hook input: %w", err)
	}

	var toolInput ToolInput
	if len(input.ToolInput) > 0 {
		_ = json.Unmarshal(input.ToolInput, &toolInput)
	}

	resolved, loadedFrom, err := loadPolicy(input.CWD)
	if err != nil {
		return err
	}

	decision := evaluate(resolved, input.ToolName, toolInput.Command)
	writeAudit(input, toolInput.Command, decision, loadedFrom)

	switch decision.Behavior {
	case "allow", "deny":
		output := HookOutput{
			HookSpecificOutput: HookSpecificOutput{
				HookEventName: "PermissionRequest",
				Decision: HookDecisionOutput{
					Behavior: decision.Behavior,
				},
			},
		}
		if decision.Behavior == "deny" {
			output.HookSpecificOutput.Decision.Message = decision.Reason
		}
		return writeJSON(out, output)
	case "ask", "":
		return nil
	default:
		return fmt.Errorf("invalid policy decision: %s", decision.Behavior)
	}
}

func runExplain(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	cwd := fs.String("cwd", "", "project directory to load project policy from")
	tool := fs.String("tool", "Bash", "Codex hook tool name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("missing command")
	}
	command := strings.Join(fs.Args(), " ")
	command = strings.Join(strings.Fields(command), " ")
	if command == "" {
		return errors.New("empty command")
	}
	if *cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		*cwd = wd
	}

	policy, loaded, err := loadPolicy(*cwd)
	if err != nil {
		return err
	}
	decision := evaluate(policy, *tool, command)

	fmt.Fprintf(out, "Command: %s\n", command)
	fmt.Fprintf(out, "Tool: %s\n", *tool)
	fmt.Fprintf(out, "Decision: %s\n", decision.Behavior)
	if decision.Source != "" {
		fmt.Fprintf(out, "Source: %s\n", decision.Source)
	}
	if decision.RuleName != "" {
		fmt.Fprintf(out, "Rule: %s\n", decision.RuleName)
	}
	if decision.Match != "" {
		fmt.Fprintf(out, "Match: %s\n", decision.Match)
	}
	if decision.Pattern != "" {
		fmt.Fprintf(out, "Pattern: %s\n", decision.Pattern)
	}
	fmt.Fprintf(out, "Reason: %s\n", decision.Reason)
	if len(loaded) > 0 {
		fmt.Fprintln(out, "Loaded policy files:")
		for _, path := range loaded {
			fmt.Fprintf(out, "  - %s\n", path)
		}
	}
	return nil
}

func runList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	cwd := fs.String("cwd", "", "project directory to load project policy from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		*cwd = wd
	}

	policy, loaded, err := loadPolicy(*cwd)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Default decision: %s\n", policy.DefaultDecision)
	if len(loaded) > 0 {
		fmt.Fprintln(out, "Loaded policy files:")
		for _, path := range loaded {
			fmt.Fprintf(out, "  - %s\n", path)
		}
	}

	for _, source := range policy.Sources {
		label := source.Name
		if source.Path != "" {
			label = fmt.Sprintf("%s (%s)", label, source.Path)
		}
		fmt.Fprintf(out, "\n%s\n", label)
		if len(source.Policy.Rules) == 0 {
			fmt.Fprintln(out, "  no rules")
			continue
		}
		for _, rule := range source.Policy.Rules {
			fmt.Fprintf(out, "  [%s] %s", rule.Decision, rule.Name)
			if len(rule.Tools) > 0 {
				fmt.Fprintf(out, " tools=%s", strings.Join(rule.Tools, ","))
			}
			fmt.Fprintf(out, " match=%s\n", matchMode(rule))
			for _, command := range rule.Commands {
				fmt.Fprintf(out, "    - %s\n", command)
			}
		}
	}
	return nil
}

func evaluate(policy ResolvedPolicy, toolName, command string) Decision {
	for _, behavior := range []string{"deny", "ask", "allow"} {
		for _, source := range policy.Sources {
			for _, rule := range source.Policy.Rules {
				if rule.Decision != behavior || !matchesTool(rule.Tools, toolName) {
					continue
				}
				if pattern, ok := matchingCommand(rule, command); ok {
					if rule.Decision == "allow" && hasShellControlOperator(command) && !allSegmentsAllowed(policy, toolName, command) {
						return Decision{
							Behavior: "ask",
							Source:   source.Name,
							RuleName: rule.Name,
							Match:    matchMode(rule),
							Pattern:  pattern,
							Reason:   "compound shell command needs explicit approval",
						}
					}
					return Decision{
						Behavior: rule.Decision,
						Source:   source.Name,
						RuleName: rule.Name,
						Match:    matchMode(rule),
						Pattern:  pattern,
						Reason:   fmt.Sprintf("matched %s rule %q", source.Name, rule.Name),
					}
				}
			}
		}
	}

	behavior := policy.DefaultDecision
	if behavior == "" {
		behavior = defaultDecision
	}
	return Decision{Behavior: behavior, Reason: "no codexgo rule matched"}
}

func allSegmentsAllowed(policy ResolvedPolicy, toolName, command string) bool {
	segments := splitShellSegments(command)
	if len(segments) <= 1 {
		return true
	}

	for _, segment := range segments {
		allowed := false
		for _, source := range policy.Sources {
			for _, rule := range source.Policy.Rules {
				if rule.Decision != "allow" || !matchesTool(rule.Tools, toolName) {
					continue
				}
				if matchesCommand(rule, segment) {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func hasShellControlOperator(command string) bool {
	return strings.Contains(command, "&&") ||
		strings.Contains(command, "||") ||
		strings.Contains(command, ";") ||
		strings.Contains(command, "|")
}

func splitShellSegments(command string) []string {
	var segments []string
	var current strings.Builder
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if ch == ';' || ch == '|' || ch == '&' {
			if ch == '&' && i+1 < len(command) && command[i+1] != '&' {
				current.WriteByte(ch)
				continue
			}
			if text := strings.TrimSpace(current.String()); text != "" {
				segments = append(segments, text)
			}
			current.Reset()
			if i+1 < len(command) && ((ch == '&' && command[i+1] == '&') || (ch == '|' && command[i+1] == '|')) {
				i++
			}
			continue
		}
		current.WriteByte(ch)
	}
	if text := strings.TrimSpace(current.String()); text != "" {
		segments = append(segments, text)
	}
	return segments
}

func matchesTool(tools []string, toolName string) bool {
	if len(tools) == 0 {
		return true
	}
	for _, tool := range tools {
		if tool == "*" || tool == toolName {
			return true
		}
	}
	return false
}

func matchesCommand(rule Rule, command string) bool {
	_, ok := matchingCommand(rule, command)
	return ok
}

func matchingCommand(rule Rule, command string) (string, bool) {
	normalized := strings.Join(strings.Fields(command), " ")
	match := matchMode(rule)

	for _, pattern := range rule.Commands {
		pattern = strings.Join(strings.Fields(pattern), " ")
		switch match {
		case "exact":
			if normalized == pattern {
				return pattern, true
			}
		case "contains":
			if strings.Contains(normalized, pattern) {
				return pattern, true
			}
		case "prefix":
			if normalized == pattern || strings.HasPrefix(normalized, pattern+" ") {
				return pattern, true
			}
		}
	}
	return "", false
}

func matchMode(rule Rule) string {
	if rule.Match == "" {
		return "prefix"
	}
	return rule.Match
}

func validDecision(decision string) bool {
	return decision == "allow" || decision == "deny" || decision == "ask"
}

func loadPolicy(cwd string) (ResolvedPolicy, []string, error) {
	resolved := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Sources: []PolicySource{
			{Name: "built-in defaults", Policy: builtInPolicy()},
		},
	}
	var loaded []string

	for _, path := range policyPaths(cwd) {
		next, ok, err := readPolicy(path)
		if err != nil {
			return ResolvedPolicy{}, nil, err
		}
		if !ok {
			continue
		}
		if next.DefaultDecision != "" {
			resolved.DefaultDecision = next.DefaultDecision
		}
		resolved.Sources = append(resolved.Sources, PolicySource{
			Name:   policySourceName(path, cwd),
			Path:   path,
			Policy: next,
		})
		loaded = append(loaded, path)
	}
	return resolved, loaded, nil
}

func policySourceName(path, cwd string) string {
	home, _ := os.UserHomeDir()
	if home != "" && path == filepath.Join(home, userPolicyPath) {
		return "user policy"
	}
	if cwd != "" && path == filepath.Join(cwd, ".codexgo", "policy.json") {
		return "project policy"
	}
	return path
}

func policyPaths(cwd string) []string {
	home, _ := os.UserHomeDir()
	var paths []string
	if home != "" {
		paths = append(paths, filepath.Join(home, userPolicyPath))
	}
	if cwd != "" {
		paths = append(paths, filepath.Join(cwd, ".codexgo", "policy.json"))
	}
	return paths
}

func readPolicy(path string) (Policy, bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, err
	}
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return Policy{}, false, fmt.Errorf("decode policy %s: %w", path, err)
	}
	return policy, true, nil
}

func builtInPolicy() Policy {
	return Policy{
		DefaultDecision: defaultDecision,
		Rules: []Rule{
			{
				Name:     "block destructive shell patterns",
				Decision: "deny",
				Tools:    []string{"Bash"},
				Match:    "contains",
				Commands: []string{
					"rm -rf /",
					"git reset --hard",
					"curl | sh",
					"curl | bash",
					"sudo ",
				},
			},
			{
				Name:     "allow read-only discovery",
				Decision: "allow",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{
					"pwd",
					"ls",
					"rg",
					"cat",
					"sed -n",
					"git status",
					"git diff",
					"git log",
					"git show",
					"go version",
					"node --version",
					"npm --version",
				},
			},
			{
				Name:     "allow common local verification",
				Decision: "allow",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{
					"go test",
					"npm test",
					"npm run test",
					"npm run lint",
					"npm run build",
					"cargo test",
					"pytest",
				},
			},
		},
	}
}

func emptyPolicy() Policy {
	return Policy{
		DefaultDecision: defaultDecision,
		Rules:           []Rule{},
	}
}

func samplePolicy() Policy {
	return builtInPolicy()
}

func runPolicyCommand(decision string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(decision, flag.ContinueOnError)
	scope := fs.String("scope", "user", "policy scope: user or project")
	match := fs.String("match", "prefix", "match mode: exact, prefix, or contains")
	tool := fs.String("tool", "Bash", "Codex hook tool name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !validDecision(decision) {
		return fmt.Errorf("invalid decision %q", decision)
	}
	if !validMatch(*match) {
		return fmt.Errorf("invalid match %q", *match)
	}
	if fs.NArg() == 0 {
		return errors.New("missing command")
	}

	command := strings.Join(fs.Args(), " ")
	command = strings.Join(strings.Fields(command), " ")
	if command == "" {
		return errors.New("empty command")
	}

	path, err := policyPathForScope(*scope)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	changed := false
	if err := withPolicyLock(path, func() error {
		policy, ok, err := readPolicy(path)
		if err != nil {
			return err
		}
		if !ok {
			policy = Policy{DefaultDecision: defaultDecision}
		}
		if policy.DefaultDecision == "" {
			policy.DefaultDecision = defaultDecision
		}

		changed = addCommandRule(&policy, Rule{
			Name:     managedRuleName(decision, *match, *tool),
			Decision: decision,
			Tools:    []string{*tool},
			Match:    *match,
			Commands: []string{command},
		})
		if !changed {
			return nil
		}
		return atomicWriteJSON(path, policy)
	}); err != nil {
		return err
	}

	if !changed {
		fmt.Fprintf(out, "No change: %s policy already sets %s for %q (match=%s, tool=%s)\n", *scope, decision, command, *match, *tool)
		fmt.Fprintf(out, "Policy: %s\n", path)
		return nil
	}

	fmt.Fprintf(out, "Set %s policy: %s %q (match=%s, tool=%s)\n", *scope, decision, command, *match, *tool)
	fmt.Fprintf(out, "Policy: %s\n", path)
	return nil
}

func runRemoveCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	scope := fs.String("scope", "user", "policy scope: user or project")
	match := fs.String("match", "prefix", "match mode: exact, prefix, or contains")
	tool := fs.String("tool", "Bash", "Codex hook tool name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !validMatch(*match) {
		return fmt.Errorf("invalid match %q", *match)
	}
	if fs.NArg() == 0 {
		return errors.New("missing command")
	}

	command := strings.Join(fs.Args(), " ")
	command = strings.Join(strings.Fields(command), " ")
	if command == "" {
		return errors.New("empty command")
	}

	path, err := policyPathForScope(*scope)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	changed := false
	if err := withPolicyLock(path, func() error {
		policy, ok, err := readPolicy(path)
		if err != nil {
			return err
		}
		if !ok {
			policy = Policy{DefaultDecision: defaultDecision}
		}
		if policy.DefaultDecision == "" {
			policy.DefaultDecision = defaultDecision
		}

		changed = removeCommandRule(&policy, []string{*tool}, *match, command)
		if !changed {
			return nil
		}
		return atomicWriteJSON(path, policy)
	}); err != nil {
		return err
	}

	if !changed {
		fmt.Fprintf(out, "No change: %s policy has no rule for %q (match=%s, tool=%s)\n", *scope, command, *match, *tool)
		fmt.Fprintf(out, "Policy: %s\n", path)
		return nil
	}

	fmt.Fprintf(out, "Removed from %s policy: %q (match=%s, tool=%s)\n", *scope, command, *match, *tool)
	fmt.Fprintf(out, "Policy: %s\n", path)
	return nil
}

func validMatch(match string) bool {
	return match == "exact" || match == "prefix" || match == "contains"
}

func policyPathForScope(scope string) (string, error) {
	switch scope {
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, userPolicyPath), nil
	case "project":
		return filepath.Join(".codexgo", "policy.json"), nil
	default:
		return "", fmt.Errorf("invalid scope %q", scope)
	}
}

func managedRuleName(decision, match, tool string) string {
	return fmt.Sprintf("codexgo %s %s %s commands", decision, match, tool)
}

func addCommandRule(policy *Policy, rule Rule) bool {
	command := rule.Commands[0]
	changed := removeCommandFromOtherRules(policy, rule, command)

	for i := range policy.Rules {
		existing := &policy.Rules[i]
		if existing.Name != rule.Name ||
			existing.Decision != rule.Decision ||
			existing.Match != rule.Match ||
			!sameStrings(existing.Tools, rule.Tools) {
			continue
		}
		for _, existingCommand := range existing.Commands {
			if existingCommand == command {
				return changed
			}
		}
		existing.Commands = append(existing.Commands, command)
		return true
	}

	policy.Rules = append(policy.Rules, rule)
	return true
}

func removeCommandFromOtherRules(policy *Policy, rule Rule, command string) bool {
	changed := false
	nextRules := policy.Rules[:0]

	for _, existing := range policy.Rules {
		if existing.Name == rule.Name &&
			existing.Decision == rule.Decision &&
			existing.Match == rule.Match &&
			sameStrings(existing.Tools, rule.Tools) {
			nextRules = append(nextRules, existing)
			continue
		}

		if !sameStrings(existing.Tools, rule.Tools) {
			nextRules = append(nextRules, existing)
			continue
		}

		nextCommands := existing.Commands[:0]
		for _, existingCommand := range existing.Commands {
			if strings.Join(strings.Fields(existingCommand), " ") == command {
				changed = true
				continue
			}
			nextCommands = append(nextCommands, existingCommand)
		}
		existing.Commands = nextCommands
		if len(existing.Commands) > 0 {
			nextRules = append(nextRules, existing)
		}
	}

	policy.Rules = nextRules
	return changed
}

func removeCommandRule(policy *Policy, tools []string, match, command string) bool {
	changed := false
	nextRules := policy.Rules[:0]

	for _, existing := range policy.Rules {
		if existing.Match != match || !sameStrings(existing.Tools, tools) {
			nextRules = append(nextRules, existing)
			continue
		}

		nextCommands := existing.Commands[:0]
		for _, existingCommand := range existing.Commands {
			if strings.Join(strings.Fields(existingCommand), " ") == command {
				changed = true
				continue
			}
			nextCommands = append(nextCommands, existingCommand)
		}
		existing.Commands = nextCommands
		if len(existing.Commands) > 0 {
			nextRules = append(nextRules, existing)
		}
	}

	policy.Rules = nextRules
	return changed
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func withPolicyLock(policyPath string, fn func() error) error {
	lockPath := policyPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	return fn()
}

func atomicWriteJSON(path string, value any) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := writeJSON(tmp, value); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

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

func runAudit() error {
	home, _ := os.UserHomeDir()
	paths := []string{filepath.Join(".codexgo", "audit.jsonl")}
	if home != "" {
		paths = append(paths, filepath.Join(home, auditPath))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		fmt.Print(string(data))
	}
	return nil
}

func writeAudit(input HookInput, command string, decision Decision, policyFiles []string) {
	path := auditFile(input.CWD)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()

	entry := map[string]any{
		"time":        time.Now().Format(time.RFC3339),
		"session_id":  input.SessionID,
		"cwd":         input.CWD,
		"tool":        input.ToolName,
		"command":     command,
		"decision":    decision.Behavior,
		"rule":        decision.RuleName,
		"reason":      decision.Reason,
		"policyFiles": policyFiles,
	}
	_ = writeJSONLine(file, entry)
}

func auditFile(cwd string) string {
	if cwd != "" {
		if _, err := os.Stat(filepath.Join(cwd, ".codexgo")); err == nil {
			return filepath.Join(cwd, ".codexgo", "audit.jsonl")
		}
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		return filepath.Join(home, auditPath)
	}
	return filepath.Join(".codexgo", "audit.jsonl")
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeJSONLine(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}
