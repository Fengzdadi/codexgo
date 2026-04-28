# Install

## macOS Installer

Install CodexGo:

```sh
curl -fsSL https://raw.githubusercontent.com/fengzdadi/codexgo/main/install.sh | sh
```

The install script currently supports macOS only. It downloads the macOS release binary and places it in `~/.local/bin/codexgo`. If `~/.local/bin` is not in your `PATH`, the installer prints the shell command to add it.

Verify the install:

```sh
codexgo version
codexgo explain "git status"
```

Install the hook for this project:

```sh
codexgo init --scope project
```

Or install it globally for your Codex user config:

```sh
codexgo init --scope user
```

Start a new Codex session after running `init` so Codex reloads hooks.

## Specific Version

Pass `CODEXGO_VERSION` to the installer:

```sh
curl -fsSL https://raw.githubusercontent.com/fengzdadi/codexgo/main/install.sh | CODEXGO_VERSION=v0.1.4 sh
```

Or download the installer first:

```sh
curl -fsSLo install.sh https://raw.githubusercontent.com/fengzdadi/codexgo/main/install.sh
CODEXGO_VERSION=v0.1.4 sh install.sh
```

You can also download `codexgo-darwin-arm64` or `codexgo-darwin-amd64` directly from the GitHub Releases page.

## Go Install

```sh
go install github.com/fengzdadi/codexgo@latest
```

To install a specific version:

```sh
go install github.com/fengzdadi/codexgo@v0.1.4
```

Make sure your Go binary directory is on your `PATH`, usually `$(go env GOPATH)/bin`.
