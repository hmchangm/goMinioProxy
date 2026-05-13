package acl_test

import (
	"testing"

	"gominioproxy/acl"
	"gominioproxy/config"
)

var testUser = config.User{
	AccessKey: "user1key",
	SecretKey: "user1secret",
	Rules: []config.Rule{
		{Prefix: "photos/", Verbs: []string{"get", "list"}},
		{Prefix: "uploads/user1/", Verbs: []string{"get", "put", "delete", "list"}},
	},
}

var readOnlyUser = config.User{
	AccessKey: "user2key",
	SecretKey: "user2secret",
	Rules: []config.Rule{
		{Prefix: "", Verbs: []string{"get", "list"}},
	},
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		name    string
		user    config.User
		path    string
		verb    acl.Verb
		allowed bool
	}{
		{"get allowed prefix", testUser, "photos/img.jpg", acl.VerbGet, true},
		{"list allowed prefix", testUser, "photos/", acl.VerbList, true},
		{"put allowed prefix", testUser, "uploads/user1/f.txt", acl.VerbPut, true},
		{"delete allowed prefix", testUser, "uploads/user1/f.txt", acl.VerbDelete, true},
		{"put denied on read-only prefix", testUser, "photos/img.jpg", acl.VerbPut, false},
		{"delete denied on read-only prefix", testUser, "photos/img.jpg", acl.VerbDelete, false},
		{"get denied wrong prefix", testUser, "uploads/user2/f.txt", acl.VerbGet, false},
		{"readonly can get anything", readOnlyUser, "any/path/file.txt", acl.VerbGet, true},
		{"readonly can list empty prefix", readOnlyUser, "", acl.VerbList, true},
		{"readonly cannot put", readOnlyUser, "any/path/file.txt", acl.VerbPut, false},
		{"readonly cannot delete", readOnlyUser, "any/path/file.txt", acl.VerbDelete, false},
		{"list scoped to allowed prefix", testUser, "photos/vacation/", acl.VerbList, true},
		{"list denied outside prefix", testUser, "other/", acl.VerbList, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := acl.Check(tc.user, tc.path, tc.verb)
			if got != tc.allowed {
				t.Errorf("Check(%q, %q, %q) = %v, want %v", tc.user.AccessKey, tc.path, tc.verb, got, tc.allowed)
			}
		})
	}
}
