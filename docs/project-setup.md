# Project Setup

For a repository-level setup, run:

```sh
codexgo init --scope project
```

This creates project-local Codex hook files:

```text
<repo>/.codex/config.toml
<repo>/.codex/hooks.json
<repo>/.codexgo/policy.json
```

Example `.codex/config.toml`:

```toml
[features]
codex_hooks = true
```

Example `.codex/hooks.json`:

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "codexgo decide",
            "timeout": 5,
            "statusMessage": "Checking CodexGo policy"
          }
        ]
      }
    ]
  }
}
```

Example `.codexgo/policy.json`:

```json
{
  "defaultDecision": "ask",
  "rules": [
    {
      "name": "codexgo allow prefix Bash commands",
      "decision": "allow",
      "tools": ["Bash"],
      "match": "prefix",
      "commands": ["git add", "git commit"]
    },
    {
      "name": "codexgo ask prefix Bash commands",
      "decision": "ask",
      "tools": ["Bash"],
      "match": "prefix",
      "commands": ["git push"]
    }
  ]
}
```

Do not commit generated `.codex/hooks.json` if it contains a local absolute path such as `/Users/.../codexgo`. Prefer committing `.codexgo/policy.json` only when the rules represent project-wide policy rather than personal workflow preferences.

## Manual Hook Block

If `hooks.json` already exists, CodexGo refuses to overwrite it. Add this block manually instead:

```json
{
  "hooks": {
    "PermissionRequest": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/codexgo decide",
            "timeout": 5,
            "statusMessage": "Checking CodexGo policy"
          }
        ]
      }
    ]
  }
}
```

## Test The Hook Handler

```sh
printf '%s\n' '{
  "session_id": "demo",
  "cwd": "'$PWD'",
  "hook_event_name": "PermissionRequest",
  "tool_name": "Bash",
  "tool_input": {
    "command": "git status",
    "description": "Check repository state"
  }
}' | codexgo decide
```

Expected output from the built-in defaults:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow"
    }
  }
}
```

View audit logs:

```sh
codexgo audit
codexgo audit --limit 20
codexgo audit --limit 0
codexgo suggest
```

By default, `audit` prints the 10 most recent entries. Use `--limit 0` to print all entries.
Use `suggest` to turn repeated `ask` entries into reviewable policy commands.
