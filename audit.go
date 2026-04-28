package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func runAudit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	limit := fs.Int("limit", 10, "number of recent audit entries to show; use 0 for all")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("audit does not accept command arguments")
	}
	if *limit < 0 {
		return fmt.Errorf("invalid limit %d", *limit)
	}

	home, _ := os.UserHomeDir()
	paths := []string{filepath.Join(".codexgo", "audit.jsonl")}
	if home != "" {
		paths = append(paths, filepath.Join(home, auditPath))
	}

	var lines [][]byte
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			copied := append([]byte(nil), line...)
			lines = append(lines, copied)
		}
	}

	start := 0
	if *limit > 0 && len(lines) > *limit {
		start = len(lines) - *limit
	}
	for _, line := range lines[start:] {
		fmt.Fprintln(out, string(line))
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
