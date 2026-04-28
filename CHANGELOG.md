# Changelog

All notable changes to CodexGo are documented here.

## Unreleased

## v0.1.2 - 2026-04-28

### Added

- Added `codexgo remove` to delete command rules from user or project policy files.
- Added project-level setup examples for `.codex/config.toml`, `.codex/hooks.json`, and `.codexgo/policy.json`.

### Changed

- Project policy now takes precedence over user policy, then built-in defaults.
- Within one policy source, decision priority remains `deny > ask > allow`.
- Policy commands now override prior decisions for the same command instead of accumulating conflicting rules.
- Policy command output now clearly reports whether a rule was set, removed, or unchanged.

## v0.1.1 - 2026-04-28

### Added

- Added macOS release assets for Apple Silicon and Intel Macs.
- Added a one-line macOS installer script that installs CodexGo into `~/.local/bin`.
- Added `codexgo version`.

### Changed

- README quick start now recommends the installer and stable release installation.

## v0.1.0 - 2026-04-28

### Added

- Added the initial Codex `PermissionRequest` hook handler.
- Added project and user policy files.
- Added `allow`, `deny`, and `ask` policy commands.
- Added `explain` and `list` inspection commands.
- Added audit logging for hook decisions.
- Added built-in default rules for low-risk discovery and local verification commands.
