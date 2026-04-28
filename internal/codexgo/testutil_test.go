package codexgo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readTestPolicy(t *testing.T, path string) Policy {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func hookInput(t *testing.T, command string) (string, string) {
	t.Helper()

	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cwd := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".codexgo"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	return cwd, `{
  "session_id": "test",
  "cwd": "` + cwd + `",
  "hook_event_name": "PermissionRequest",
  "tool_name": "Bash",
  "tool_input": {
    "command": "` + command + `",
    "description": "test command"
  }
}`
}
