// auth/sigv4.go
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ParsedAuth holds the fields extracted from an AWS4-HMAC-SHA256 Authorization header.
type ParsedAuth struct {
	AccessKey     string
	Date          string
	Region        string
	Service       string
	SignedHeaders  []string
	Signature     string
}

// ParseAuthHeader extracts auth fields from the incoming request's Authorization header.
func ParseAuthHeader(r *http.Request) (*ParsedAuth, error) {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(raw, prefix) {
		return nil, fmt.Errorf("unsupported auth scheme")
	}
	raw = strings.TrimPrefix(raw, prefix)

	parts := strings.Split(raw, ", ")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed Authorization: expected 3 parts, got %d", len(parts))
	}

	credKV := strings.SplitN(parts[0], "=", 2)
	if len(credKV) != 2 || credKV[0] != "Credential" {
		return nil, fmt.Errorf("missing Credential field")
	}
	credParts := strings.Split(credKV[1], "/")
	if len(credParts) != 5 {
		return nil, fmt.Errorf("invalid Credential format: %q", credKV[1])
	}

	shKV := strings.SplitN(parts[1], "=", 2)
	if len(shKV) != 2 || shKV[0] != "SignedHeaders" {
		return nil, fmt.Errorf("missing SignedHeaders field")
	}

	sigKV := strings.SplitN(parts[2], "=", 2)
	if len(sigKV) != 2 || sigKV[0] != "Signature" {
		return nil, fmt.Errorf("missing Signature field")
	}

	return &ParsedAuth{
		AccessKey:    credParts[0],
		Date:         credParts[1],
		Region:       credParts[2],
		Service:      credParts[3],
		SignedHeaders: strings.Split(shKV[1], ";"),
		Signature:    sigKV[1],
	}, nil
}

// ValidateSignature recomputes the SigV4 signature for r using secretKey and compares it
// to the signature in parsed. Returns an error if they do not match.
func ValidateSignature(r *http.Request, parsed *ParsedAuth, secretKey string) error {
	canon := canonicalRequest(r, parsed.SignedHeaders)
	dateTime := r.Header.Get("X-Amz-Date")
	scope := parsed.Date + "/" + parsed.Region + "/" + parsed.Service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateTime,
		scope,
		hexSHA256([]byte(canon)),
	}, "\n")
	key := signingKey(secretKey, parsed.Date, parsed.Region, parsed.Service)
	expected := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
	if expected != parsed.Signature {
		return fmt.Errorf("signature does not match")
	}
	return nil
}

func canonicalRequest(r *http.Request, signedHeaders []string) string {
	return strings.Join([]string{
		r.Method,
		canonicalURI(r.URL),
		canonicalQueryString(r.URL),
		canonicalHeaders(r, signedHeaders),
		strings.Join(signedHeaders, ";"),
		payloadHash(r),
	}, "\n")
}

func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			decoded = seg
		}
		segments[i] = uriEncode(decoded)
	}
	return strings.Join(segments, "/")
}

func canonicalQueryString(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	params := strings.Split(u.RawQuery, "&")
	pairs := make([]string, 0, len(params))
	for _, p := range params {
		kv := strings.SplitN(p, "=", 2)
		k, _ := url.PathUnescape(kv[0])
		v := ""
		if len(kv) == 2 {
			v, _ = url.PathUnescape(kv[1])
		}
		pairs = append(pairs, uriEncode(k)+"="+uriEncode(v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func canonicalHeaders(r *http.Request, signedHeaders []string) string {
	var b strings.Builder
	for _, h := range signedHeaders {
		var val string
		if h == "host" {
			val = r.Host
		} else {
			vals := r.Header[http.CanonicalHeaderKey(h)]
			trimmed := make([]string, len(vals))
			for i, v := range vals {
				trimmed[i] = strings.Join(strings.Fields(v), " ")
			}
			val = strings.Join(trimmed, ",")
		}
		b.WriteString(h)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(val))
		b.WriteByte('\n')
	}
	return b.String()
}

func payloadHash(r *http.Request) string {
	if h := r.Header.Get("X-Amz-Content-Sha256"); h != "" {
		return h
	}
	// SHA256 of empty string
	return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func signingKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
