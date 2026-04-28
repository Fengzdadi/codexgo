# CodexGo

CodexGo is a small policy layer for Codex `PermissionRequest` hooks. It lets Codex auto-approve low-risk shell approvals, deny known-dangerous patterns, and fall back to the normal Codex prompt when no rule matches.

## Why this exists

Codex App can ask for approval many times during ordinary development. Codex already exposes a hook point before the approval prompt is shown. CodexGo installs a handler for that hook:

```text
Codex PermissionRequest -> codexgo decide -> allow / deny / no decision
```

No decision means Codex keeps its normal approval dialog.

## Install locally

Build the CLI:

```sh
go build -o ./bin/codexgo .
```

Install the hook for your Codex user config:

```sh
./bin/codexgo init --scope user --bin "$(pwd)/bin/codexgo"
```

Or install it only for this project:

```sh
./bin/codexgo init --scope project --bin "$(pwd)/bin/codexgo"
```

For this repository, the GitHub remote is:

```text
https://github.com/Fengzdadi/codexgo
```

`init` writes:

- `config.toml` with `codex_hooks = true`
- `hooks.json` with a `PermissionRequest` hook for `Bash`
- `.codexgo/policy.json` with starter rules

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

## Policy

Most users should add rules with the CLI:

```sh
./bin/codexgo allow "git status"
./bin/codexgo allow --scope project "npm run lint"
./bin/codexgo deny --scope user "git reset --hard"
./bin/codexgo ask --match exact "npm install lodash"
```

By default these commands use `--scope user`, `--tool Bash`, and `--match prefix`.

User policy lives at:

```text
~/.codexgo/policy.json
```

Project policy lives at:

```text
<repo>/.codexgo/policy.json
```

Project rules are loaded after user rules. A policy looks like:

```json
{
  "defaultDecision": "ask",
  "rules": [
    {
      "name": "allow read-only discovery",
      "decision": "allow",
      "tools": ["Bash"],
      "match": "prefix",
      "commands": ["pwd", "ls", "rg", "git status", "git diff"]
    }
  ]
}
```

Rule decisions:

- `allow`: CodexGo approves the request and Codex does not show the prompt.
- `deny`: CodexGo blocks the request.
- `ask`: CodexGo declines to decide, so Codex shows the normal prompt.

Rule match modes:

- `exact`: command must match exactly after whitespace normalization.
- `prefix`: command must equal the pattern or start with `pattern + space`.
- `contains`: command must contain the pattern.

The CLI writes ordinary policy JSON, so you can still edit the file by hand for bulk changes.

## Test the hook handler

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
}' | ./bin/codexgo decide
```

Expected output for the starter policy:

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
./bin/codexgo audit
```
