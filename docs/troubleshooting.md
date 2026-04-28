# Troubleshooting

## Codex Still Prompts

If Codex still prompts for a command that `codexgo explain` says should be allowed:

- Start a new Codex session for the workspace so hooks are reloaded.
- Confirm hooks are enabled in `.codex/config.toml` or `~/.codex/config.toml`.
- Confirm `hooks.json` points to the absolute path of the `codexgo` binary.
- Check whether `.codexgo/audit.jsonl` received a new entry.
- Remember that CodexGo does not revoke sandbox approvals already granted in the surrounding Codex runtime or current session.

If the audit log has no new entry, Codex did not invoke the hook. If the audit log shows `decision: allow` but Codex still prompts, the prompt is coming from another permission or sandbox layer.

## Global Command Looks Outdated

If `./bin/codexgo` behaves differently from `codexgo`, check which binary your shell is using:

```sh
which codexgo
codexgo version
./bin/codexgo version
```

During local development, `./bin/codexgo` may contain unreleased changes while `codexgo` points to an older global install in `~/.local/bin`.

To test the local build through the global command:

```sh
cp ./bin/codexgo ~/.local/bin/codexgo
```

## Profile Looks Missing

Run:

```sh
codexgo list
```

If `Profile: go` is missing, the effective policy stack did not load a `go` profile. Enable it for the current project:

```sh
codexgo go --scope project
```

Return to manual mode:

```sh
codexgo manual --scope project
```
