// proxy/proxy.go
package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"gominioproxy/acl"
	"gominioproxy/auth"
	"gominioproxy/config"
)

// Proxy implements http.Handler. It validates SigV4, enforces ACL, re-signs, and streams.
type Proxy struct {
	cfg        *config.Config
	userMap    map[string]config.User
	minioBase  string
	httpClient *http.Client
	signer     *v4.Signer
}

// New constructs a Proxy from cfg.
func New(cfg *config.Config) *Proxy {
	userMap := make(map[string]config.User, len(cfg.Users))
	for _, u := range cfg.Users {
		userMap[u.AccessKey] = u
	}
	scheme := "http"
	if cfg.MinIO.UseSSL {
		scheme = "https"
	}
	return &Proxy{
		cfg:        cfg,
		userMap:    userMap,
		minioBase:  scheme + "://" + cfg.MinIO.Endpoint,
		httpClient: &http.Client{},
		signer:     v4.NewSigner(),
	}
}

func parseOperation(r *http.Request, bucket string) (acl.Verb, string, error) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	bucketName := ""
	if len(parts) > 0 {
		bucketName = parts[0]
	}
	if bucketName != bucket {
		return "", "", fmt.Errorf("unknown bucket %q", bucketName)
	}
	objectKey := ""
	if len(parts) == 2 {
		objectKey = parts[1]
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if objectKey == "" {
			return acl.VerbList, r.URL.Query().Get("prefix"), nil
		}
		return acl.VerbGet, objectKey, nil
	case http.MethodPut:
		if objectKey == "" {
			return "", "", fmt.Errorf("PutObject requires an object key")
		}
		return acl.VerbPut, objectKey, nil
	case http.MethodDelete:
		if objectKey == "" {
			return "", "", fmt.Errorf("DeleteObject requires an object key")
		}
		return acl.VerbDelete, objectKey, nil
	default:
		return "", "", fmt.Errorf("unsupported method %q", r.Method)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parsed, err := auth.ParseAuthHeader(r)
	if err != nil {
		writeS3Error(w, "InvalidAccessKeyId", "Missing or malformed Authorization", http.StatusForbidden)
		return
	}

	user, ok := p.userMap[parsed.AccessKey]
	if !ok {
		writeS3Error(w, "InvalidAccessKeyId", "The access key does not exist", http.StatusForbidden)
		return
	}

	if err := auth.ValidateSignature(r, parsed, user.SecretKey); err != nil {
		writeS3Error(w, "SignatureDoesNotMatch", "The request signature does not match", http.StatusForbidden)
		return
	}

	verb, aclPath, err := parseOperation(r, p.cfg.MinIO.Bucket)
	if err != nil {
		writeS3Error(w, "InvalidRequest", err.Error(), http.StatusBadRequest)
		return
	}

	if !acl.Check(user, aclPath, verb) {
		writeS3Error(w, "AccessDenied", "Access Denied", http.StatusForbidden)
		return
	}

	p.forward(w, r)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	upstreamURL := p.minioBase + r.URL.RequestURI()
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		writeS3Error(w, "InternalError", "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	outReq.ContentLength = r.ContentLength

	skipHeaders := map[string]bool{
		"Authorization":         true,
		"X-Amz-Date":           true,
		"X-Amz-Security-Token": true,
	}
	for k, vs := range r.Header {
		if !skipHeaders[k] {
			outReq.Header[k] = vs
		}
	}
	outReq.Host = p.cfg.MinIO.Endpoint

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	creds := aws.Credentials{
		AccessKeyID:     p.cfg.MinIO.AccessKey,
		SecretAccessKey: p.cfg.MinIO.SecretKey,
	}
	if err := p.signer.SignHTTP(r.Context(), creds, outReq, payloadHash, "s3", "us-east-1", time.Now()); err != nil {
		writeS3Error(w, "InternalError", "failed to sign upstream request", http.StatusInternalServerError)
		return
	}

	resp, err := p.httpClient.Do(outReq)
	if err != nil {
		writeS3Error(w, "InternalError", "upstream unreachable", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck — client disconnect is non-fatal
}

func writeS3Error(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><RequestId>1</RequestId></Error>`, code, message)
}
