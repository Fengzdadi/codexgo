package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

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
