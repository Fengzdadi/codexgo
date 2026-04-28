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
	for _, source := range policy.Sources {
		for _, behavior := range []string{"deny", "ask", "allow"} {
			for _, rule := range source.Policy.Rules {
				if rule.Decision != behavior || !matchesTool(rule.Tools, toolName) {
					continue
				}
				if pattern, ok := matchingCommand(rule, command); ok {
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

func isComplexShellCommand(command string) bool {
	return hasShellControlOperator(command) ||
		strings.Contains(command, "$(") ||
		strings.Contains(command, "`") ||
		strings.Contains(command, ">") ||
		strings.Contains(command, "<") ||
		strings.Contains(command, "*") ||
		strings.Contains(command, "?")
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
