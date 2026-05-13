package acl

import (
	"strings"

	"gominioproxy/config"
)

type Verb string

const (
	VerbGet    Verb = "get"
	VerbPut    Verb = "put"
	VerbDelete Verb = "delete"
	VerbList   Verb = "list"
)

// Check returns true if user may perform verb on path.
// For list operations pass the requested prefix query param as path.
func Check(user config.User, path string, verb Verb) bool {
	for _, rule := range user.Rules {
		if hasVerb(rule, verb) && strings.HasPrefix(path, rule.Prefix) {
			return true
		}
	}
	return false
}

func hasVerb(rule config.Rule, verb Verb) bool {
	for _, v := range rule.Verbs {
		if Verb(v) == verb {
			return true
		}
	}
	return false
}
