package main

func builtInPolicy() Policy {
	return Policy{
		DefaultDecision: defaultDecision,
		Rules: []Rule{
			{
				Name:     "block destructive shell patterns",
				Decision: "deny",
				Tools:    []string{"Bash"},
				Match:    "contains",
				Commands: []string{
					"rm -rf /",
					"git reset --hard",
					"curl | sh",
					"curl | bash",
					"sudo ",
				},
			},
			{
				Name:     "allow read-only discovery",
				Decision: "allow",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{
					"pwd",
					"ls",
					"rg",
					"cat",
					"sed -n",
					"git status",
					"git diff",
					"git log",
					"git show",
					"go version",
					"node --version",
					"npm --version",
				},
			},
			{
				Name:     "allow common local verification",
				Decision: "allow",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{
					"go test",
					"npm test",
					"npm run test",
					"npm run lint",
					"npm run build",
					"cargo test",
					"pytest",
				},
			},
		},
	}
}

func goProfilePolicy() Policy {
	return Policy{
		DefaultDecision: defaultDecision,
		Profile:         goProfile,
		Rules: []Rule{
			{
				Name:     "block dangerous go profile commands",
				Decision: "deny",
				Tools:    []string{"Bash"},
				Match:    "contains",
				Commands: []string{
					"rm -rf /",
					"rm -rf ~",
					"rm -rf $HOME",
					"sudo rm",
					"chmod -R 777 /",
					"chown -R",
					"dd if=",
					"mkfs",
					"diskutil erase",
					"git reset --hard",
					"git clean -fdx",
					"git push --force",
					"git push -f",
				},
			},
			{
				Name:     "ask destructive go profile commands",
				Decision: "ask",
				Tools:    []string{"Bash"},
				Match:    "contains",
				Commands: []string{
					"rm -rf",
					"rm -r",
					"find . -delete",
				},
			},
			{
				Name:     "ask sensitive go profile commands",
				Decision: "ask",
				Tools:    []string{"Bash"},
				Match:    "prefix",
				Commands: []string{
					"git push",
					"git rebase",
					"git commit --amend",
					"npm publish",
					"gh release delete",
					"docker system prune",
					"brew uninstall",
				},
			},
		},
	}
}

func emptyPolicy() Policy {
	return Policy{
		DefaultDecision: defaultDecision,
		Rules:           []Rule{},
	}
}

func samplePolicy() Policy {
	return builtInPolicy()
}
