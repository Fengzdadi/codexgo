package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func validDecision(decision string) bool {
	return decision == "allow" || decision == "deny" || decision == "ask"
}

func loadPolicy(cwd string) (ResolvedPolicy, []string, error) {
	resolved := ResolvedPolicy{
		Sources: []PolicySource{},
	}
	var loaded []string

	for _, path := range sourcePriorityPolicyPaths(cwd) {
		next, ok, err := readPolicy(path)
		if err != nil {
			return ResolvedPolicy{}, nil, err
		}
		if !ok {
			continue
		}
		if next.DefaultDecision != "" && resolved.DefaultDecision == "" {
			resolved.DefaultDecision = next.DefaultDecision
		}
		sourceName := policySourceName(path, cwd)
		if next.Profile != "" && resolved.Profile == "" {
			resolved.Profile = next.Profile
			resolved.ProfileSource = sourceName
			resolved.ProfilePath = path
		}
		resolved.Sources = append(resolved.Sources, PolicySource{
			Name:   sourceName,
			Path:   path,
			Policy: next,
		})
		loaded = append(loaded, path)
	}
	if resolved.DefaultDecision == "" {
		resolved.DefaultDecision = defaultDecision
	}
	if resolved.Profile == goProfile {
		resolved.Sources = append(resolved.Sources, PolicySource{Name: "go profile", Policy: goProfilePolicy()})
	}
	resolved.Sources = append(resolved.Sources, PolicySource{Name: "built-in defaults", Policy: builtInPolicy()})
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

func sourcePriorityPolicyPaths(cwd string) []string {
	all := policyPaths(cwd)
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
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
