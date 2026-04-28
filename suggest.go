package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type AuditEntry struct {
	CWD         string   `json:"cwd"`
	Tool        string   `json:"tool"`
	Command     string   `json:"command"`
	Decision    string   `json:"decision"`
	Rule        string   `json:"rule"`
	Reason      string   `json:"reason"`
	PolicyFiles []string `json:"policyFiles"`
}

type commandSuggestion struct {
	Pattern  string
	Decision string
	Match    string
	Reason   string
	Count    int
	Examples []string
}

func runSuggest(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	limit := fs.Int("limit", 10, "number of suggestions to show; use 0 for all")
	auditLimit := fs.Int("audit-limit", 100, "number of recent audit entries to analyze; use 0 for all")
	scope := fs.String("scope", "project", "policy scope to use in suggested commands: user or project")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("suggest does not accept command arguments")
	}
	if *limit < 0 {
		return fmt.Errorf("invalid limit %d", *limit)
	}
	if *auditLimit < 0 {
		return fmt.Errorf("invalid audit-limit %d", *auditLimit)
	}
	if _, err := policyPathForScope(*scope); err != nil {
		return err
	}

	entries, err := readAuditEntries(*auditLimit)
	if err != nil {
		return err
	}
	suggestions := suggestFromAudit(entries)
	if len(suggestions) == 0 {
		fmt.Fprintln(out, "No ask entries found in recent audit logs.")
		return nil
	}
	total := len(suggestions)
	if *limit > 0 && len(suggestions) > *limit {
		suggestions = suggestions[:*limit]
	}

	fmt.Fprintf(out, "Suggestions from recent audit asks (showing: %d/%d, audit limit: %d)\n", len(suggestions), total, *auditLimit)
	fmt.Fprintf(out, "Scope for commands: %s\n\n", *scope)
	for i, suggestion := range suggestions {
		fmt.Fprintf(out, "%d. %s\n", i+1, suggestion.Pattern)
		fmt.Fprintf(out, "   seen: %d\n", suggestion.Count)
		fmt.Fprintf(out, "   suggestion: %s", suggestion.Decision)
		if suggestion.Decision != "review" {
			fmt.Fprintf(out, " %s", suggestion.Match)
		}
		fmt.Fprintln(out)
		fmt.Fprintf(out, "   reason: %s\n", suggestion.Reason)
		if suggestion.Decision == "review" {
			fmt.Fprintln(out, "   command: inspect manually before adding a policy rule")
		} else {
			fmt.Fprintf(out, "   command: codexgo %s --scope %s --match %s %s\n", suggestion.Decision, *scope, suggestion.Match, shellQuote(suggestion.Pattern))
		}
		if len(suggestion.Examples) > 0 && suggestion.Examples[0] != suggestion.Pattern {
			fmt.Fprintf(out, "   example: %s\n", suggestion.Examples[0])
		}
		if i != len(suggestions)-1 {
			fmt.Fprintln(out)
		}
	}
	return nil
}

func readAuditEntries(limit int) ([]AuditEntry, error) {
	var lines [][]byte
	for _, path := range auditLogPaths() {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			lines = append(lines, append([]byte(nil), line...))
		}
	}

	start := 0
	if limit > 0 && len(lines) > limit {
		start = len(lines) - limit
	}

	var entries []AuditEntry
	for _, line := range lines[start:] {
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func suggestFromAudit(entries []AuditEntry) []commandSuggestion {
	byPattern := map[string]*commandSuggestion{}
	for _, entry := range entries {
		if entry.Decision != "ask" || entry.Command == "" {
			continue
		}
		for _, command := range suggestionCommands(entry.Command) {
			pattern, match := suggestionPattern(command)
			decision, reason := suggestionDecision(pattern, command)
			key := decision + "\x00" + match + "\x00" + pattern
			suggestion := byPattern[key]
			if suggestion == nil {
				suggestion = &commandSuggestion{
					Pattern:  pattern,
					Decision: decision,
					Match:    match,
					Reason:   reason,
				}
				byPattern[key] = suggestion
			}
			suggestion.Count++
			if len(suggestion.Examples) < 3 {
				example := normalizeCommand(command)
				if !containsString(suggestion.Examples, example) {
					suggestion.Examples = append(suggestion.Examples, example)
				}
			}
		}
	}

	suggestions := make([]commandSuggestion, 0, len(byPattern))
	for _, suggestion := range byPattern {
		suggestions = append(suggestions, *suggestion)
	}
	sort.Slice(suggestions, func(i, j int) bool {
		if suggestions[i].Count != suggestions[j].Count {
			return suggestions[i].Count > suggestions[j].Count
		}
		return suggestions[i].Pattern < suggestions[j].Pattern
	})
	return suggestions
}

func suggestionCommands(command string) []string {
	normalized := normalizeCommand(command)
	if normalized == "" {
		return nil
	}
	lower := strings.ToLower(normalized)
	if hasRemoteShellPipe(normalized) || isReadOnlyNetworkPipe(lower) {
		return []string{normalized}
	}
	segments := splitShellSegments(normalized)
	if len(segments) <= 1 {
		return []string{normalized}
	}
	return segments
}

func suggestionPattern(command string) (string, string) {
	normalized := normalizeCommand(command)
	lower := strings.ToLower(normalized)

	for _, known := range []string{
		"git commit --amend",
		"git reset --hard",
		"git clean -fdx",
		"git push --force",
		"git push -f",
		"git commit",
		"git add",
		"git push",
		"git rebase",
		"go test",
		"npm run build",
		"npm run lint",
		"npm run test",
		"npm test",
		"cargo test",
		"pytest",
		"npm publish",
		"gh release delete",
		"docker system prune",
		"brew uninstall",
	} {
		if lower == known || strings.HasPrefix(lower, known+" ") {
			return known, "prefix"
		}
	}

	if isReadOnlyNetworkPipe(lower) {
		return normalized, "exact"
	}
	return normalized, "exact"
}

func suggestionDecision(pattern, command string) (string, string) {
	lowerPattern := strings.ToLower(pattern)
	lowerCommand := strings.ToLower(normalizeCommand(command))

	if isDangerousSuggestion(lowerPattern) || isDangerousSuggestion(lowerCommand) {
		return "deny", "dangerous command pattern"
	}
	if isSensitiveSuggestion(lowerPattern) {
		return "ask", "sensitive command should keep an explicit confirmation"
	}
	if isCommonLocalSuggestion(lowerPattern) || isReadOnlyNetworkPipe(lowerCommand) {
		return "allow", "common local development or read-only inspection command"
	}
	return "review", "not enough built-in context to suggest a safe policy decision"
}

func isDangerousSuggestion(command string) bool {
	for _, pattern := range []string{
		"rm -rf /",
		"rm -rf ~",
		"rm -rf $home",
		"sudo rm",
		"chmod -r 777 /",
		"chown -r",
		"dd if=",
		"mkfs",
		"diskutil erase",
		"git reset --hard",
		"git clean -fdx",
		"git push --force",
		"git push -f",
		"| sh",
		"| bash",
		"| zsh",
	} {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
}

func isSensitiveSuggestion(command string) bool {
	for _, pattern := range []string{
		"git push",
		"git rebase",
		"git commit --amend",
		"npm publish",
		"gh release delete",
		"docker system prune",
		"brew uninstall",
	} {
		if command == pattern || strings.HasPrefix(command, pattern+" ") {
			return true
		}
	}
	return false
}

func isCommonLocalSuggestion(command string) bool {
	for _, pattern := range []string{
		"git add",
		"git commit",
		"go test",
		"npm test",
		"npm run test",
		"npm run lint",
		"npm run build",
		"cargo test",
		"pytest",
	} {
		if command == pattern || strings.HasPrefix(command, pattern+" ") {
			return true
		}
	}
	return false
}

func isReadOnlyNetworkPipe(command string) bool {
	segments := splitShellSegments(command)
	if len(segments) != 2 {
		return false
	}
	left := strings.ToLower(normalizeCommand(segments[0]))
	right := strings.ToLower(normalizeCommand(segments[1]))
	return (strings.HasPrefix(left, "curl ") || strings.HasPrefix(left, "wget ")) &&
		(right == "rg" || strings.HasPrefix(right, "rg "))
}

func normalizeCommand(command string) string {
	return strings.Join(strings.Fields(command), " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
