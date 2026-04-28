package main

import "encoding/json"

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
	Profile         string `json:"profile,omitempty"`
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
	Profile         string
	ProfileSource   string
	ProfilePath     string
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
