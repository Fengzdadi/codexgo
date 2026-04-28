package main

import (
	"fmt"
	"os"
)

const (
	version         = "v0.1.3"
	defaultDecision = "ask"
	goProfile       = "go"
	userPolicyPath  = ".codexgo/policy.json"
	auditPath       = ".codexgo/audit.jsonl"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "decide":
		err = runDecide(os.Stdin, os.Stdout)
	case "init":
		err = runInit(os.Args[2:])
	case "allow", "deny", "ask":
		err = runPolicyCommand(os.Args[1], os.Args[2:], os.Stdout)
	case "go":
		err = runGoCommand(os.Args[2:], os.Stdout)
	case "manual":
		err = runManualCommand(os.Args[2:], os.Stdout)
	case "remove":
		err = runRemoveCommand(os.Args[2:], os.Stdout)
	case "explain":
		err = runExplain(os.Args[2:], os.Stdout)
	case "list":
		err = runList(os.Args[2:], os.Stdout)
	case "profile":
		err = runProfile(os.Args[2:], os.Stdout)
	case "doctor":
		err = runDoctor(os.Args[2:], os.Stdout)
	case "sample-policy":
		err = writeJSON(os.Stdout, samplePolicy())
	case "audit":
		err = runAudit(os.Args[2:], os.Stdout)
	case "suggest":
		err = runSuggest(os.Args[2:], os.Stdout)
	case "version":
		fmt.Fprintf(os.Stdout, "CodexGo %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "codexgo:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `codexgo manages Codex PermissionRequest approvals.

Usage:
  codexgo init [--scope user|project] [--bin /path/to/codexgo]
  codexgo allow [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo deny  [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo ask   [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo go [--scope user|project]
  codexgo manual [--scope user|project]
  codexgo remove [--scope user|project] [--match exact|prefix|contains] <command>
  codexgo explain [--cwd /path/to/project] [--tool Bash] <command>
  codexgo list [--cwd /path/to/project]
  codexgo profile [--cwd /path/to/project]
  codexgo doctor [--cwd /path/to/project]
  codexgo decide
  codexgo sample-policy
  codexgo audit [--limit 10]
  codexgo suggest [--limit 10] [--audit-limit 100] [--scope user|project]
  codexgo version`)
}
