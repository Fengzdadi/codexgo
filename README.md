# CodexGo

CodexGo is a small policy layer for Codex `PermissionRequest` hooks. It lets Codex auto-approve low-risk shell approvals, deny known-dangerous patterns, and fall back to the normal Codex prompt when no rule matches.

## Quick Start

Install CodexGo:

```sh
curl -fsSL https://raw.githubusercontent.com/fengzdadi/codexgo/main/install.sh | sh
```

Install the hook for your Codex user config:

```sh
codexgo init --scope user
```

To install a specific version, pass `CODEXGO_VERSION` to the installer:

```sh
curl -fsSL https://raw.githubusercontent.com/fengzdadi/codexgo/main/install.sh | CODEXGO_VERSION=v0.1.1 sh
```

Or download the installer first with `curl`:

```sh
curl -fsSLo install.sh https://raw.githubusercontent.com/fengzdadi/codexgo/main/install.sh
CODEXGO_VERSION=v0.1.1 sh install.sh
```

The installer downloads the macOS release binary and places it in `~/.local/bin/codexgo`. If `~/.local/bin` is not in your `PATH`, the installer prints the shell command to add it.

Or install it only for this project:

```sh
codexgo init --scope project
```

Add project-specific approvals:

```sh
codexgo allow --scope project "git add"
codexgo allow --scope project "git commit"
codexgo deny --scope project "git push"
```

Check what will happen before using Codex:

```sh
codexgo explain "git commit -m test"
codexgo list
```

`init` writes:

- `config.toml` with `codex_hooks = true`
- `hooks.json` with a `PermissionRequest` hook for `Bash`
- `.codexgo/policy.json` for rules you explicitly add

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

## Why this exists

Codex App can ask for approval many times during ordinary development. Codex already exposes a hook point before the approval prompt is shown. CodexGo installs a handler for that hook:

```text
Codex PermissionRequest -> codexgo decide -> allow / deny / no decision
```

No decision means Codex keeps its normal approval dialog.

CodexGo only handles Codex `PermissionRequest` hooks. It does not disable operating system permissions, Git protections, network authentication, or any separate sandbox layer outside Codex hooks.

## Policy

Most users should add rules with the CLI:

```sh
codexgo allow "git status"
codexgo allow --scope project "npm run lint"
codexgo deny --scope user "git reset --hard"
codexgo ask --match exact "npm install lodash"
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

CodexGo always starts with built-in defaults, then loads user rules, then project rules. The built-in defaults are not copied into policy files, so local policy only stores rules you explicitly add.

Built-in defaults currently auto-allow read-only discovery commands such as `pwd`, `ls`, `rg`, `git status`, `git diff`, `git log`, and common local verification commands such as `go test`, `npm test`, and `pytest`. Destructive patterns such as `git reset --hard` and remote shell execution patterns such as `curl | sh` are denied.

A policy looks like:

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

The CLI writes ordinary policy JSON, so you can still edit the file by hand for bulk changes. An empty policy is valid:

```json
{
  "defaultDecision": "ask",
  "rules": []
}
```

## Inspect Decisions

Use `explain` to see why a command would be allowed, denied, or sent back to the Codex prompt:

```sh
codexgo explain "git status --short"
codexgo explain "git commit -m test"
codexgo explain "npm install react"
```

Example:

```text
Command: git commit -m test
Tool: Bash
Decision: allow
Source: project policy
Rule: codexgo allow prefix Bash commands
Match: prefix
Pattern: git commit
Reason: matched project policy rule "codexgo allow prefix Bash commands"
```

Use `list` to view the effective policy stack:

```sh
codexgo list
```

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
```

## Troubleshooting

If Codex still prompts for a command that `codexgo explain` says should be allowed:

- Start a new Codex session for the workspace so hooks are reloaded.
- Confirm hooks are enabled in `.codex/config.toml` or `~/.codex/config.toml`.
- Confirm `hooks.json` points to the absolute path of the `codexgo` binary.
- Check whether `.codexgo/audit.jsonl` received a new entry.

If the audit log has no new entry, Codex did not invoke the hook. If the audit log shows `decision: allow` but Codex still prompts, the prompt is coming from another permission or sandbox layer.
