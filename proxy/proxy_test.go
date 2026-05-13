// proxy/proxy_test.go
package proxy

import (
	"net/http"
	"testing"

	"gominioproxy/acl"
)

func TestParseOperation(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		url         string
		wantVerb    acl.Verb
		wantPath    string
		wantErr     bool
	}{
		{
			name: "get object",
			method: "GET", url: "http://proxy/my-bucket/photos/img.jpg",
			wantVerb: acl.VerbGet, wantPath: "photos/img.jpg",
		},
		{
			name: "head object",
			method: "HEAD", url: "http://proxy/my-bucket/docs/file.pdf",
			wantVerb: acl.VerbGet, wantPath: "docs/file.pdf",
		},
		{
			name: "put object",
			method: "PUT", url: "http://proxy/my-bucket/uploads/user1/data.csv",
			wantVerb: acl.VerbPut, wantPath: "uploads/user1/data.csv",
		},
		{
			name: "delete object",
			method: "DELETE", url: "http://proxy/my-bucket/uploads/user1/old.txt",
			wantVerb: acl.VerbDelete, wantPath: "uploads/user1/old.txt",
		},
		{
			name: "list objects no prefix",
			method: "GET", url: "http://proxy/my-bucket?list-type=2",
			wantVerb: acl.VerbList, wantPath: "",
		},
		{
			name: "list objects with prefix",
			method: "GET", url: "http://proxy/my-bucket?list-type=2&prefix=photos/",
			wantVerb: acl.VerbList, wantPath: "photos/",
		},
		{
			name: "wrong bucket",
			method: "GET", url: "http://proxy/other-bucket/key",
			wantErr: true,
		},
		{
			name: "put without key",
			method: "PUT", url: "http://proxy/my-bucket",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(tc.method, tc.url, nil)
			verb, path, err := parseOperation(r, "my-bucket")
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verb != tc.wantVerb {
				t.Errorf("got verb %q, want %q", verb, tc.wantVerb)
			}
			if path != tc.wantPath {
				t.Errorf("got path %q, want %q", path, tc.wantPath)
			}
		})
	}
}
