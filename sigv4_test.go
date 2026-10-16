package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	testSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	emptySHA256         = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func testAuth(now time.Time) *sigV4Auth {
	return &sigV4Auth{accessKeyID: testAccessKeyID, secretAccessKey: testSecretAccessKey, now: func() time.Time { return now }}
}

// The examples in AWS's "Signature Calculations for the Authorization
// Header" and "Authenticating Requests: Using Query Parameters" pages:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
func TestSigV4AWSExamples(t *testing.T) {
	auth := testAuth(time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	credential := "Credential=" + testAccessKeyID + "/20130524/us-east-1/s3/aws4_request"
	cases := []struct {
		name, method, target, body string
		header                     map[string]string
	}{
		{"GET object", http.MethodGet, "/test.txt", "", map[string]string{
			"Range":                "bytes=0-9",
			"X-Amz-Content-Sha256": emptySHA256,
			"X-Amz-Date":           "20130524T000000Z",
			"Authorization": "AWS4-HMAC-SHA256 " + credential + ",SignedHeaders=host;range;x-amz-content-sha256;x-amz-date," +
				"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		}},
		{"PUT object", http.MethodPut, "/test$file.text", "Welcome to Amazon S3.", map[string]string{
			"Date":                 "Fri, 24 May 2013 00:00:00 GMT",
			"X-Amz-Date":           "20130524T000000Z",
			"X-Amz-Storage-Class":  "REDUCED_REDUNDANCY",
			"X-Amz-Content-Sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			"Authorization": "AWS4-HMAC-SHA256 " + credential + ",SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class," +
				"Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		}},
		{"GET bucket lifecycle", http.MethodGet, "/?lifecycle", "", map[string]string{
			"X-Amz-Date":           "20130524T000000Z",
			"X-Amz-Content-Sha256": emptySHA256,
			"Authorization": "AWS4-HMAC-SHA256 " + credential + ",SignedHeaders=host;x-amz-content-sha256;x-amz-date," +
				"Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		}},
		{"list objects", http.MethodGet, "/?max-keys=2&prefix=J", "", map[string]string{
			"X-Amz-Date":           "20130524T000000Z",
			"X-Amz-Content-Sha256": emptySHA256,
			"Authorization": "AWS4-HMAC-SHA256 " + credential + ",SignedHeaders=host;x-amz-content-sha256;x-amz-date," +
				"Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		}},
		{"presigned GET", http.MethodGet, "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
			"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
			"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" +
			"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", "", nil},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "http://examplebucket.s3.amazonaws.com"+tc.target, strings.NewReader(tc.body))
		for name, value := range tc.header {
			req.Header.Set(name, value)
		}
		if err := auth.check(req); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		// Any change to a signed part breaks the signature.
		req.Host = "otherbucket.s3.amazonaws.com"
		if err := auth.check(req); err != errSignatureMismatch {
			t.Errorf("%s with another host: err = %v, want SignatureDoesNotMatch", tc.name, err)
		}
	}
}

// signRequest signs req with SigV4 in its Authorization header, covering
// host, x-amz-* and any extra headers, and the body's SHA-256.
func signRequest(t *testing.T, req *http.Request, accessKeyID, secret string, at time.Time, extra ...string) {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		sum := sha256.Sum256(body)
		req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(sum[:]))
	}
	req.Header.Set("X-Amz-Date", at.UTC().Format(amzDateFormat))
	signed := append([]string{"host"}, extra...)
	for name := range req.Header {
		if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-amz-") {
			signed = append(signed, lower)
		}
	}
	sort.Strings(signed)
	date := at.UTC().Format("20060102")
	scope := date + "/us-east-1/s3/aws4_request"
	sreq := sigV4Request{signedHeaders: signed, payloadHash: req.Header.Get("X-Amz-Content-Sha256")}
	query, _ := url.ParseQuery(req.URL.RawQuery)
	canonical, err := canonicalRequest(req, query, sreq)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigV4Signature(secret, date, "us-east-1", stringToSign(req.Header.Get("X-Amz-Date"), scope, canonical))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/"+scope+
		", SignedHeaders="+strings.Join(signed, ";")+", Signature="+hex.EncodeToString(sig))
}

// presign returns target with a presigned URL's query parameters, signing
// only the host.
func presign(t *testing.T, method, target string, at time.Time, expires int) string {
	t.Helper()
	date := at.UTC().Format("20060102")
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("X-Amz-Algorithm", sigV4Algorithm)
	query.Set("X-Amz-Credential", testAccessKeyID+"/"+date+"/us-east-1/s3/aws4_request")
	query.Set("X-Amz-Date", at.UTC().Format(amzDateFormat))
	query.Set("X-Amz-Expires", strconv.Itoa(expires))
	query.Set("X-Amz-SignedHeaders", "host")
	u.RawQuery = query.Encode()
	req := httptest.NewRequest(method, u.String(), nil)
	sreq := sigV4Request{signedHeaders: []string{"host"}, payloadHash: unsignedPayload, presigned: true}
	canonical, err := canonicalRequest(req, query, sreq)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigV4Signature(testSecretAccessKey, date, "us-east-1", stringToSign(query.Get("X-Amz-Date"), date+"/us-east-1/s3/aws4_request", canonical))
	return u.String() + "&X-Amz-Signature=" + hex.EncodeToString(sig)
}

func TestSigV4Handler(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	dir, _ := newTestDir(t)
	handler := testAuth(now).wrap(newHandler(dir))

	send := func(req *http.Request) (int, string, string) {
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		var doc s3Error
		_ = xml.Unmarshal(resp.Body.Bytes(), &doc)
		return resp.Code, doc.Code, resp.Body.String()
	}
	signed := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		signRequest(t, req, testAccessKeyID, testSecretAccessKey, now)
		return req
	}

	for _, req := range []*http.Request{
		signed(http.MethodPut, "/secure", ""),
		signed(http.MethodPut, "/secure/a%20b/%C3%BCn%C3%AFcode%2Bkey", "hello"),
		signed(http.MethodGet, "/secure/a%20b/%C3%BCn%C3%AFcode%2Bkey", ""),
		signed(http.MethodGet, "/secure?list-type=2&prefix=a%20b/&max-keys=10", ""),
	} {
		if code, _, body := send(req); code != http.StatusOK {
			t.Fatalf("signed %s %s: status = %d %s", req.Method, req.URL, code, body)
		}
	}
	if code, _, body := send(httptest.NewRequest(http.MethodGet, presign(t, http.MethodGet, "/secure/a%20b/%C3%BCn%C3%AFcode%2Bkey", now.Add(-time.Hour), 3600), nil)); code != http.StatusOK || body != "hello" {
		t.Fatalf("presigned GET: status = %d %q", code, body)
	}

	rejected := []struct {
		name   string
		req    func() *http.Request
		status int
		code   string
	}{
		{"unsigned", func() *http.Request { return httptest.NewRequest(http.MethodGet, "/secure/k", nil) }, http.StatusForbidden, "AccessDenied"},
		{"wrong secret", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/secure/k", nil)
			signRequest(t, req, testAccessKeyID, "not-the-secret", now)
			return req
		}, http.StatusForbidden, "SignatureDoesNotMatch"},
		{"unknown key", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/secure/k", nil)
			signRequest(t, req, "AKIDOTHER", testSecretAccessKey, now)
			return req
		}, http.StatusForbidden, "InvalidAccessKeyId"},
		{"other method", func() *http.Request {
			req := signed(http.MethodGet, "/secure/k", "")
			req.Method = http.MethodDelete
			return req
		}, http.StatusForbidden, "SignatureDoesNotMatch"},
		{"other key", func() *http.Request {
			req := signed(http.MethodGet, "/secure/k", "")
			req.URL.Path = "/secure/other"
			return req
		}, http.StatusForbidden, "SignatureDoesNotMatch"},
		{"added query parameter", func() *http.Request {
			req := signed(http.MethodGet, "/secure?list-type=2", "")
			req.URL.RawQuery += "&prefix=x"
			return req
		}, http.StatusForbidden, "SignatureDoesNotMatch"},
		{"unsigned x-amz header", func() *http.Request {
			req := signed(http.MethodGet, "/secure/k", "")
			req.Header.Set("X-Amz-Checksum-Mode", "ENABLED")
			return req
		}, http.StatusForbidden, "AccessDenied"},
		{"changed body", func() *http.Request {
			req := signed(http.MethodPut, "/secure/k", "signed")
			req.Body = io.NopCloser(strings.NewReader("tampered"))
			return req
		}, http.StatusBadRequest, "XAmzContentSHA256Mismatch"},
		{"no content sha256", func() *http.Request {
			req := signed(http.MethodGet, "/secure/k", "")
			req.Header.Del("X-Amz-Content-Sha256")
			return req
		}, http.StatusBadRequest, "InvalidRequest"},
		{"too old", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/secure/k", nil)
			signRequest(t, req, testAccessKeyID, testSecretAccessKey, now.Add(-16*time.Minute))
			return req
		}, http.StatusForbidden, "RequestTimeTooSkewed"},
		{"from the future", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/secure/k", nil)
			signRequest(t, req, testAccessKeyID, testSecretAccessKey, now.Add(16*time.Minute))
			return req
		}, http.StatusForbidden, "RequestTimeTooSkewed"},
		{"other service", func() *http.Request {
			req := signed(http.MethodGet, "/secure/k", "")
			req.Header.Set("Authorization", strings.Replace(req.Header.Get("Authorization"), "/s3/", "/sqs/", 1))
			return req
		}, http.StatusBadRequest, "AuthorizationHeaderMalformed"},
		{"other algorithm", func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/secure/k", nil)
			req.Header.Set("Authorization", "AWS "+testAccessKeyID+":c2lnbmF0dXJl")
			return req
		}, http.StatusBadRequest, "InvalidArgument"},
		{"header and query", func() *http.Request {
			req := signed(http.MethodGet, "/secure/k", "")
			req.URL.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
			return req
		}, http.StatusBadRequest, "InvalidArgument"},
		{"expired presigned URL", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, presign(t, http.MethodGet, "/secure/k", now.Add(-2*time.Hour), 3600), nil)
		}, http.StatusForbidden, "AccessDenied"},
		{"presigned URL for another method", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, presign(t, http.MethodGet, "/secure/k", now, 3600), strings.NewReader("x"))
		}, http.StatusForbidden, "SignatureDoesNotMatch"},
		{"presigned URL too long", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, presign(t, http.MethodGet, "/secure/k", now, maxPresignSeconds+1), nil)
		}, http.StatusBadRequest, "AuthorizationQueryParametersError"},
		{"presigned URL missing parameters", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/secure/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc", nil)
		}, http.StatusBadRequest, "AuthorizationQueryParametersError"},
	}
	for _, tc := range rejected {
		code, s3code, body := send(tc.req())
		if code != tc.status || s3code != tc.code {
			t.Errorf("%s: got %d %q, want %d %q (%s)", tc.name, code, s3code, tc.status, tc.code, body)
		}
	}

	// Rejected requests change nothing, and HEAD errors carry no body.
	if code, _, body := send(signed(http.MethodGet, "/secure/k", "")); code != http.StatusNotFound {
		t.Errorf("GET k after rejected writes: status = %d %s", code, body)
	}
	if code, _, body := send(httptest.NewRequest(http.MethodHead, "/secure/a%20b/%C3%BCn%C3%AFcode%2Bkey", nil)); code != http.StatusForbidden || body != "" {
		t.Errorf("unsigned HEAD: status = %d body = %q", code, body)
	}
}

func TestAuthFromEnv(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}
	// FEATHERD_AUTH is required, even alongside the key pair.
	if auth, err := authFromEnv(env(nil)); auth != nil || err == nil {
		t.Errorf("no vars: auth = %v, err = %v", auth, err)
	}
	if auth, err := authFromEnv(env(map[string]string{authEnvAccessKeyID: "id", authEnvSecretAccessKey: "secret"})); auth != nil || err == nil {
		t.Errorf("key pair without %s: auth = %v, err = %v", authEnvMode, auth, err)
	}
	if auth, err := authFromEnv(env(map[string]string{authEnvMode: authModeNone})); auth != nil || err != nil {
		t.Errorf("%s=%s: auth = %v, err = %v", authEnvMode, authModeNone, auth, err)
	}
	// FEATHERD_AUTH=sigv4 needs the key pair.
	auth, err := authFromEnv(env(map[string]string{authEnvMode: authModeSigV4, authEnvAccessKeyID: "id", authEnvSecretAccessKey: "secret"}))
	if err != nil || auth == nil || auth.accessKeyID != "id" || auth.secretAccessKey != "secret" {
		t.Errorf("%s=%s with both vars: auth = %v, err = %v", authEnvMode, authModeSigV4, auth, err)
	}
	if auth, err := authFromEnv(env(map[string]string{authEnvMode: authModeSigV4})); auth != nil || err == nil {
		t.Errorf("%s=%s alone: auth = %v, err = %v", authEnvMode, authModeSigV4, auth, err)
	}
	for _, name := range []string{authEnvAccessKeyID, authEnvSecretAccessKey} {
		if auth, err := authFromEnv(env(map[string]string{name: "x", authEnvMode: authModeSigV4})); auth != nil || err == nil {
			t.Errorf("only %s with %s=%s: auth = %v, err = %v", name, authEnvMode, authModeSigV4, auth, err)
		}
		// A key alongside FEATHERD_AUTH=none is ambiguous, so neither wins.
		if auth, err := authFromEnv(env(map[string]string{name: "x", authEnvMode: authModeNone})); auth != nil || err == nil {
			t.Errorf("%s with %s=%s: auth = %v, err = %v", name, authEnvMode, authModeNone, auth, err)
		}
	}
	for _, mode := range []string{"None", "off", "0", "SigV4", "public-read"} {
		if auth, err := authFromEnv(env(map[string]string{authEnvMode: mode})); auth != nil || err == nil {
			t.Errorf("%s=%s: auth = %v, err = %v", authEnvMode, mode, auth, err)
		}
	}
}
