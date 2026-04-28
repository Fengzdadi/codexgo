package codexgo

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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
	if decision.Source == "go profile" {
		printOverrideHelp(out, "project", *tool, command, decision)
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
	if policy.Profile != "" {
		fmt.Fprintf(out, "Profile: %s\n", policy.Profile)
	}
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

func runProfile(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	cwd := fs.String("cwd", "", "project directory to load project policy from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("profile does not accept command arguments")
	}
	if *cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		*cwd = wd
	}

	policy, _, err := loadPolicy(*cwd)
	if err != nil {
		return err
	}

	profile := policy.Profile
	source := policy.ProfileSource
	path := policy.ProfilePath
	if profile == "" {
		profile = "manual"
		source = "default"
		path = "none"
	}

	fmt.Fprintf(out, "Effective profile: %s\n", profile)
	fmt.Fprintf(out, "Source: %s\n", source)
	fmt.Fprintf(out, "Policy: %s\n", path)
	fmt.Fprintf(out, "Default decision: %s\n", policy.DefaultDecision)
	return nil
}

func runGoCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("go", flag.ContinueOnError)
	scope := fs.String("scope", "user", "policy scope: user or project")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("go does not accept command arguments")
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

		if policy.Profile == goProfile {
			return nil
		}
		policy.Profile = goProfile
		changed = true
		return atomicWriteJSON(path, policy)
	}); err != nil {
		return err
	}

	if !changed {
		fmt.Fprintf(out, "No change: %s policy already uses %q profile\n", *scope, goProfile)
		fmt.Fprintf(out, "Policy: %s\n", path)
		return nil
	}

	fmt.Fprintf(out, "Enabled %q profile for %s policy\n", goProfile, *scope)
	fmt.Fprintln(out, "Unmatched simple commands will be allowed; dangerous commands are denied; sensitive commands ask.")
	fmt.Fprintf(out, "Policy: %s\n", path)
	return nil
}

func runManualCommand(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("manual", flag.ContinueOnError)
	scope := fs.String("scope", "user", "policy scope: user or project")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("manual does not accept command arguments")
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

		if policy.Profile == "" {
			return nil
		}
		policy.Profile = ""
		changed = true
		return atomicWriteJSON(path, policy)
	}); err != nil {
		return err
	}

	if !changed {
		fmt.Fprintf(out, "No change: %s policy already uses manual profile\n", *scope)
		fmt.Fprintf(out, "Policy: %s\n", path)
		return nil
	}

	fmt.Fprintf(out, "Enabled manual profile for %s policy\n", *scope)
	fmt.Fprintln(out, "Unmatched commands will return to the normal Codex prompt.")
	fmt.Fprintf(out, "Policy: %s\n", path)
	return nil
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

	previousDecision := Decision{}
	if wd, err := os.Getwd(); err == nil {
		if policy, _, err := loadPolicy(wd); err == nil {
			previousDecision = evaluate(policy, *tool, command)
		}
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
	if previousDecision.Source == "go profile" {
		if previousDecision.Behavior != decision {
			fmt.Fprintf(out, "This overrides go profile decision: %s", previousDecision.Behavior)
			if previousDecision.RuleName != "" {
				fmt.Fprintf(out, " (%s)", previousDecision.RuleName)
			}
			fmt.Fprintln(out)
		} else {
			fmt.Fprintln(out, "This pins the existing go profile decision in your policy.")
		}
		fmt.Fprintf(out, "Remove it to return to the go profile default: codexgo remove --scope %s --match %s %s\n", *scope, *match, shellQuote(command))
	}
	fmt.Fprintf(out, "Policy: %s\n", path)
	return nil
}

func printOverrideHelp(out io.Writer, scope, tool, command string, decision Decision) {
	pattern, match := overridePattern(command, decision)
	fmt.Fprintln(out, "Override:")
	for _, behavior := range []string{"allow", "ask", "deny"} {
		if behavior == decision.Behavior {
			continue
		}
		fmt.Fprintf(out, "  %s\n", policyCommandString(behavior, scope, tool, match, pattern))
	}
}

func policyCommandString(behavior, scope, tool, match, command string) string {
	parts := []string{"codexgo", behavior, "--scope", scope}
	if tool != "Bash" {
		parts = append(parts, "--tool", shellQuote(tool))
	}
	parts = append(parts, "--match", match, shellQuote(command))
	return strings.Join(parts, " ")
}

func overridePattern(command string, decision Decision) (string, string) {
	if decision.Pattern != "" {
		match := decision.Match
		if match == "" {
			match = "prefix"
		}
		return decision.Pattern, match
	}
	pattern, match := suggestionPattern(command)
	return pattern, match
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
