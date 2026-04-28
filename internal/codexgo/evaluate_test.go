package codexgo

import "testing"

func TestEvaluateAskOverridesAllow(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Sources: []PolicySource{
			{
				Name: "test policy",
				Policy: Policy{
					DefaultDecision: defaultDecision,
					Rules: []Rule{
						{
							Name:     "allow push",
							Decision: "allow",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git push"},
						},
						{
							Name:     "ask push",
							Decision: "ask",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git push"},
						},
					},
				},
			},
		},
	}

	decision := evaluate(policy, "Bash", "git push")
	if decision.Behavior != "ask" || decision.RuleName != "ask push" {
		t.Fatalf("expected ask to override allow, got %#v", decision)
	}
}

func TestEvaluateDenyOverridesAsk(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Sources: []PolicySource{
			{
				Name: "test policy",
				Policy: Policy{
					DefaultDecision: defaultDecision,
					Rules: []Rule{
						{
							Name:     "ask reset",
							Decision: "ask",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git reset"},
						},
						{
							Name:     "deny reset",
							Decision: "deny",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git reset"},
						},
					},
				},
			},
		},
	}

	decision := evaluate(policy, "Bash", "git reset --hard HEAD")
	if decision.Behavior != "deny" || decision.RuleName != "deny reset" {
		t.Fatalf("expected deny to override ask, got %#v", decision)
	}
}

func TestEvaluateProjectOverridesUser(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Sources: []PolicySource{
			{
				Name: "project policy",
				Policy: Policy{
					DefaultDecision: defaultDecision,
					Rules: []Rule{
						{
							Name:     "project allow push",
							Decision: "allow",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git push"},
						},
					},
				},
			},
			{
				Name: "user policy",
				Policy: Policy{
					DefaultDecision: defaultDecision,
					Rules: []Rule{
						{
							Name:     "user ask push",
							Decision: "ask",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git push"},
						},
					},
				},
			},
		},
	}

	decision := evaluate(policy, "Bash", "git push")
	if decision.Behavior != "allow" || decision.Source != "project policy" {
		t.Fatalf("expected project allow to override user ask, got %#v", decision)
	}
}

func TestEvaluateUserOverridesBuiltIn(t *testing.T) {
	policy := ResolvedPolicy{
		DefaultDecision: defaultDecision,
		Sources: []PolicySource{
			{
				Name: "user policy",
				Policy: Policy{
					DefaultDecision: defaultDecision,
					Rules: []Rule{
						{
							Name:     "user allow reset",
							Decision: "allow",
							Tools:    []string{"Bash"},
							Match:    "prefix",
							Commands: []string{"git reset"},
						},
					},
				},
			},
			{
				Name:   "built-in defaults",
				Policy: builtInPolicy(),
			},
		},
	}

	decision := evaluate(policy, "Bash", "git reset --hard HEAD")
	if decision.Behavior != "allow" || decision.Source != "user policy" {
		t.Fatalf("expected user allow to override built-in deny, got %#v", decision)
	}
}
