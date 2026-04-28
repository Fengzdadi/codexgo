package main

import (
	"fmt"
	"strings"
)

func evaluate(policy ResolvedPolicy, toolName, command string) Decision {
	if hasRemoteShellPipe(command) {
		return Decision{
			Behavior: "deny",
			Source:   "built-in defaults",
			RuleName: "block remote shell execution",
			Reason:   "remote shell execution is dangerous",
		}
	}
	if hasShellControlOperator(command) && policy.Profile == goProfile {
		return evaluateGoProfileCompoundCommand(policy, toolName, command)
	}
	if !hasShellControlOperator(command) {
		return evaluateSimpleCommand(policy, toolName, command)
	}

	for _, source := range policy.Sources {
		for _, behavior := range []string{"deny", "ask", "allow"} {
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

	if policy.Profile == goProfile {
		if isComplexShellCommand(command) {
			return Decision{
				Behavior: "ask",
				Source:   "go profile",
				Reason:   "complex shell command needs explicit approval",
			}
		}
		return Decision{
			Behavior: "allow",
			Source:   "go profile",
			Reason:   "go profile allows unmatched commands",
		}
	}

	behavior := policy.DefaultDecision
	if behavior == "" {
		behavior = defaultDecision
	}
	return Decision{Behavior: behavior, Reason: "no codexgo rule matched"}
}

func evaluateGoProfileCompoundCommand(policy ResolvedPolicy, toolName, command string) Decision {
	segments := splitShellSegments(command)
	if len(segments) <= 1 {
		return evaluateSimpleCommand(policy, toolName, command)
	}

	for _, segment := range segments {
		decision := evaluateSimpleCommand(policy, toolName, segment)
		if decision.Behavior == "deny" {
			decision.Reason = fmt.Sprintf("compound shell segment denied: %s", decision.Reason)
			return decision
		}
		if decision.Behavior == "ask" || decision.Behavior == "" {
			decision.Behavior = "ask"
			decision.Reason = fmt.Sprintf("compound shell segment needs approval: %s", decision.Reason)
			return decision
		}
	}

	return Decision{
		Behavior: "allow",
		Source:   "go profile",
		Reason:   "all compound shell segments are allowed by go profile",
	}
}

func evaluateSimpleCommand(policy ResolvedPolicy, toolName, command string) Decision {
	matchCommand := stripLeadingEnvAssignments(command)
	for _, source := range policy.Sources {
		for _, behavior := range []string{"deny", "ask"} {
			for _, rule := range source.Policy.Rules {
				if rule.Decision != behavior || !matchesTool(rule.Tools, toolName) {
					continue
				}
				if pattern, ok := matchingCommand(rule, matchCommand); ok {
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

		if policy.Profile == goProfile {
			if decision, ok := goProfileSyntaxDecision(command, matchCommand); ok {
				return decision
			}
		}

		for _, rule := range source.Policy.Rules {
			if rule.Decision != "allow" || !matchesTool(rule.Tools, toolName) {
				continue
			}
			if pattern, ok := matchingCommand(rule, matchCommand); ok {
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

	if policy.Profile == goProfile {
		return Decision{
			Behavior: "allow",
			Source:   "go profile",
			Reason:   "go profile allows unmatched commands",
		}
	}

	behavior := policy.DefaultDecision
	if behavior == "" {
		behavior = defaultDecision
	}
	return Decision{Behavior: behavior, Reason: "no codexgo rule matched"}
}

func goProfileSyntaxDecision(command, matchCommand string) (Decision, bool) {
	if hasComplexEnvAssignment(command) {
		return Decision{
			Behavior: "ask",
			Source:   "go profile",
			Reason:   "environment assignment needs explicit approval",
		}, true
	}
	if hasSubshell(matchCommand) {
		return Decision{
			Behavior: "ask",
			Source:   "go profile",
			Reason:   "subshell command needs explicit approval",
		}, true
	}
	if hasRedirection(matchCommand) {
		return Decision{
			Behavior: "ask",
			Source:   "go profile",
			Reason:   "file redirection needs explicit approval",
		}, true
	}
	if isDownloadToFileCommand(matchCommand) {
		return Decision{
			Behavior: "ask",
			Source:   "go profile",
			Reason:   "download writing to a file needs explicit approval",
		}, true
	}
	if isComplexShellCommand(matchCommand) {
		return Decision{
			Behavior: "ask",
			Source:   "go profile",
			Reason:   "complex shell command needs explicit approval",
		}, true
	}
	return Decision{}, false
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
	return len(splitShellSegments(command)) > 1
}

func isComplexShellCommand(command string) bool {
	return hasShellControlOperator(command) ||
		containsUnquoted(command, "$(") ||
		containsUnquoted(command, "`") ||
		hasRedirection(command) ||
		hasUnquotedGlob(command)
}

func hasRedirection(command string) bool {
	return containsUnquoted(command, ">") || containsUnquoted(command, "<")
}

func hasSubshell(command string) bool {
	return containsUnquoted(command, "(") || containsUnquoted(command, ")")
}

func hasUnquotedGlob(command string) bool {
	return containsUnquoted(command, "*") || containsUnquoted(command, "?")
}

func hasRemoteShellPipe(command string) bool {
	segments := splitShellSegments(command)
	if len(segments) < 2 {
		return false
	}

	for i := 0; i < len(segments)-1; i++ {
		left := strings.Join(strings.Fields(segments[i]), " ")
		right := strings.Join(strings.Fields(segments[i+1]), " ")
		if (strings.HasPrefix(left, "curl ") || strings.HasPrefix(left, "wget ")) &&
			(right == "sh" || strings.HasPrefix(right, "sh ") ||
				right == "bash" || strings.HasPrefix(right, "bash ") ||
				right == "zsh" || strings.HasPrefix(right, "zsh ")) {
			return true
		}
	}
	return false
}

func splitShellSegments(command string) []string {
	var segments []string
	var current strings.Builder
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			current.WriteByte(ch)
			escaped = true
			continue
		}
		if quote != 0 {
			current.WriteByte(ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			current.WriteByte(ch)
			quote = ch
			continue
		}
		switch ch {
		case ';', '|':
			if text := strings.TrimSpace(current.String()); text != "" {
				segments = append(segments, text)
			}
			current.Reset()
			if ch == '|' && i+1 < len(command) && command[i+1] == '|' {
				i++
			}
			continue
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				if text := strings.TrimSpace(current.String()); text != "" {
					segments = append(segments, text)
				}
				current.Reset()
				i++
				continue
			}
		}
		current.WriteByte(ch)
	}
	if text := strings.TrimSpace(current.String()); text != "" {
		segments = append(segments, text)
	}
	return segments
}

func stripLeadingEnvAssignments(command string) string {
	fields := shellFields(command)
	if len(fields) == 0 {
		return command
	}
	i := 0
	for i < len(fields) && isEnvAssignment(fields[i]) {
		i++
	}
	if i == 0 {
		return command
	}
	if i >= len(fields) {
		return command
	}
	return strings.Join(fields[i:], " ")
}

func hasComplexEnvAssignment(command string) bool {
	fields := shellFields(command)
	for _, field := range fields {
		if !isEnvAssignment(field) {
			return false
		}
		if strings.Contains(field, "$(") || strings.Contains(field, "`") {
			return true
		}
	}
	return false
}

func isEnvAssignment(field string) bool {
	eq := strings.IndexByte(field, '=')
	if eq <= 0 {
		return false
	}
	name := field[:eq]
	for i, r := range name {
		if i == 0 {
			if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				return false
			}
			continue
		}
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func isDownloadToFileCommand(command string) bool {
	fields := shellFields(command)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "curl":
		for i := 1; i < len(fields); i++ {
			field := fields[i]
			if field == "-o" || field == "--output" || field == "-O" || strings.HasPrefix(field, "--output=") {
				return true
			}
			if strings.HasPrefix(field, "-") && !strings.HasPrefix(field, "--") &&
				(strings.Contains(field[1:], "o") || strings.Contains(field[1:], "O")) {
				return true
			}
		}
	case "wget":
		for i := 1; i < len(fields); i++ {
			field := fields[i]
			if field == "-O" || field == "--output-document" || strings.HasPrefix(field, "--output-document=") {
				return true
			}
			if strings.HasPrefix(field, "-O") && field != "-O" {
				return true
			}
		}
	}
	return false
}

func shellFields(command string) []string {
	var fields []string
	var current strings.Builder
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
				continue
			}
			current.WriteByte(ch)
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\n' {
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
			continue
		}
		current.WriteByte(ch)
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

func containsUnquoted(command, needle string) bool {
	if needle == "" {
		return false
	}
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			quote = ch
			continue
		}
		if strings.HasPrefix(command[i:], needle) {
			return true
		}
	}
	return false
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
