package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AWS Signature Version 4, as S3 checks it:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
const (
	sigV4Algorithm  = "AWS4-HMAC-SHA256"
	sigV4Terminator = "aws4_request"
	sigV4Service    = "s3"
	amzDateFormat   = "20060102T150405Z"
	// S3 rejects requests whose x-amz-date is further than this from its clock.
	maxClockSkew = 15 * time.Minute
	// A presigned URL can be valid for at most 7 days.
	maxPresignSeconds = 7 * 24 * 60 * 60
	unsignedPayload   = "UNSIGNED-PAYLOAD"
)

// authEnvAccessKeyID and authEnvSecretAccessKey name the environment
// variables holding the one key pair featherd accepts. authEnvMode must name
// the mode, so neither signed requests nor running without authentication is
// a default.
const (
	authEnvAccessKeyID     = "FEATHERD_ACCESS_KEY_ID"
	authEnvSecretAccessKey = "FEATHERD_SECRET_ACCESS_KEY"
	authEnvMode            = "FEATHERD_AUTH"
	authModeNone           = "none"
	authModeSigV4          = "sigv4"
)

// sigV4Auth requires every request to be signed with SigV4 by one key pair,
// either in the Authorization header or as a presigned URL. featherd has no
// regions, so any region in the credential scope is accepted; the signature
// still covers it.
type sigV4Auth struct {
	accessKeyID     string
	secretAccessKey string
	now             func() time.Time
}

// authFromEnv returns the key pair from FEATHERD_ACCESS_KEY_ID and
// FEATHERD_SECRET_ACCESS_KEY when FEATHERD_AUTH=sigv4, or nil when
// FEATHERD_AUTH=none turns authentication off. FEATHERD_AUTH is required and
// anything else is an error, so a missing or misspelled variable can't leave
// the server open, and the mode is always written down where it's deployed.
func authFromEnv(getenv func(string) string) (*sigV4Auth, error) {
	id, secret, mode := getenv(authEnvAccessKeyID), getenv(authEnvSecretAccessKey), getenv(authEnvMode)
	switch mode {
	case authModeSigV4:
		switch {
		case id == "" && secret == "":
			return nil, fmt.Errorf("%s=%s needs %s and %s", authEnvMode, authModeSigV4, authEnvAccessKeyID, authEnvSecretAccessKey)
		case id == "":
			return nil, fmt.Errorf("%s is set but %s is not", authEnvSecretAccessKey, authEnvAccessKeyID)
		case secret == "":
			return nil, fmt.Errorf("%s is set but %s is not", authEnvAccessKeyID, authEnvSecretAccessKey)
		}
		return &sigV4Auth{accessKeyID: id, secretAccessKey: secret, now: time.Now}, nil
	case authModeNone:
		if id != "" || secret != "" {
			return nil, fmt.Errorf("%s=%s conflicts with %s and %s; unset one or the other", authEnvMode, authModeNone, authEnvAccessKeyID, authEnvSecretAccessKey)
		}
		return nil, nil
	case "":
		return nil, fmt.Errorf("set %s=%s with %s and %s to require signed requests, or %s=%s to serve every request without authentication", authEnvMode, authModeSigV4, authEnvAccessKeyID, authEnvSecretAccessKey, authEnvMode, authModeNone)
	default:
		return nil, fmt.Errorf("%s=%q is not supported; use %q or %q", authEnvMode, mode, authModeSigV4, authModeNone)
	}
}

// authError is a rejected request's S3 error.
type authError struct {
	status  int
	code    string
	message string
}

func (e *authError) Error() string { return e.code + ": " + e.message }

func accessDenied(message string) *authError {
	return &authError{http.StatusForbidden, "AccessDenied", message}
}

func malformedHeader(message string) *authError {
	return &authError{http.StatusBadRequest, "AuthorizationHeaderMalformed", message}
}

func malformedQuery(message string) *authError {
	return &authError{http.StatusBadRequest, "AuthorizationQueryParametersError", message}
}

var errSignatureMismatch = &authError{http.StatusForbidden, "SignatureDoesNotMatch",
	"The request signature we calculated does not match the signature you provided. Check your key and signing method."}

// wrap serves next only those requests that are signed with a's key pair.
// The check runs before the body is read; the body itself is covered by
// x-amz-content-sha256, which the handler verifies on writes.
func (a *sigV4Auth) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := a.check(r); err != nil {
			var ae *authError
			if !errors.As(err, &ae) {
				ae = accessDenied(err.Error())
			}
			writeError(w, r, ae.status, ae.code, ae.message)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sigV4Request is a request's signature and what it claims to sign.
type sigV4Request struct {
	credential    string
	signedHeaders []string
	signature     string
	amzDate       string
	payloadHash   string
	presigned     bool
	expires       int
}

func (a *sigV4Auth) check(r *http.Request) error {
	header := r.Header.Get("Authorization")
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return &authError{http.StatusBadRequest, "InvalidArgument", "The query string could not be parsed."}
	}
	presigned := query.Has("X-Amz-Algorithm") || query.Has("X-Amz-Signature") || query.Has("X-Amz-Credential")
	var req sigV4Request
	switch {
	case header != "" && presigned:
		return &authError{http.StatusBadRequest, "InvalidArgument", "Only one auth mechanism allowed; only the X-Amz-Algorithm query parameter or the Authorization header should be specified"}
	case header != "":
		req, err = parseAuthorizationHeader(r, header)
	case presigned:
		req, err = parsePresignedQuery(r, query)
	default:
		return accessDenied("Access Denied")
	}
	if err != nil {
		return err
	}

	scope, err := a.checkCredential(req)
	if err != nil {
		return err
	}
	date, err := time.Parse(amzDateFormat, req.amzDate)
	if err != nil {
		return a.malformed(req, "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"")
	}
	if scope[1] != req.amzDate[:8] {
		return a.malformed(req, "The credential's date "+scope[1]+" does not match X-Amz-Date "+req.amzDate[:8]+".")
	}
	now := a.now()
	if req.presigned {
		if date.Sub(now) > maxClockSkew {
			return accessDenied("Request is not valid yet")
		}
		if now.After(date.Add(time.Duration(req.expires) * time.Second)) {
			return accessDenied("Request has expired")
		}
	} else if d := now.Sub(date); d > maxClockSkew || d < -maxClockSkew {
		return &authError{http.StatusForbidden, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large."}
	}

	if err := checkSignedHeaders(r, req.signedHeaders); err != nil {
		return err
	}
	canonical, err := canonicalRequest(r, query, req)
	if err != nil {
		return err
	}
	scopeString := strings.Join(scope[1:], "/")
	want := sigV4Signature(a.secretAccessKey, scope[1], scope[2], stringToSign(req.amzDate, scopeString, canonical))
	got, err := hex.DecodeString(req.signature)
	if err != nil || !hmac.Equal(got, want) {
		return errSignatureMismatch
	}
	return nil
}

// checkCredential checks the credential, <key-id>/<date>/<region>/s3/aws4_request,
// and returns it split on "/".
func (a *sigV4Auth) checkCredential(req sigV4Request) ([]string, error) {
	scope := strings.Split(req.credential, "/")
	if len(scope) != 5 || scope[0] == "" || scope[2] == "" {
		return nil, a.malformed(req, "The credential must be <access-key-id>/<date>/<region>/s3/aws4_request.")
	}
	if scope[0] != a.accessKeyID {
		return nil, &authError{http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records."}
	}
	if len(scope[1]) != 8 {
		return nil, a.malformed(req, "The credential's date must be yyyyMMdd.")
	}
	if scope[3] != sigV4Service {
		return nil, a.malformed(req, "The credential's service must be s3, not "+strconv.Quote(scope[3])+".")
	}
	if scope[4] != sigV4Terminator {
		return nil, a.malformed(req, "The credential must end in aws4_request.")
	}
	return scope, nil
}

func (a *sigV4Auth) malformed(req sigV4Request, message string) error {
	if req.presigned {
		return malformedQuery(message)
	}
	return malformedHeader(message)
}

// parseAuthorizationHeader parses
// "AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...".
func parseAuthorizationHeader(r *http.Request, header string) (sigV4Request, error) {
	algorithm, rest, _ := strings.Cut(header, " ")
	if algorithm != sigV4Algorithm {
		return sigV4Request{}, &authError{http.StatusBadRequest, "InvalidArgument", "Unsupported Authorization Type; only " + sigV4Algorithm + " is supported."}
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return sigV4Request{}, malformedHeader("The authorization header is malformed.")
		}
		fields[name] = value
	}
	req := sigV4Request{
		credential:  fields["Credential"],
		signature:   fields["Signature"],
		amzDate:     r.Header.Get("X-Amz-Date"),
		payloadHash: r.Header.Get("X-Amz-Content-Sha256"),
	}
	if req.credential == "" || fields["SignedHeaders"] == "" || req.signature == "" {
		return sigV4Request{}, malformedHeader("The authorization header must have Credential, SignedHeaders and Signature.")
	}
	req.signedHeaders = strings.Split(fields["SignedHeaders"], ";")
	if req.amzDate == "" {
		return sigV4Request{}, accessDenied("AWS authentication requires a valid X-Amz-Date header")
	}
	if req.payloadHash == "" {
		return sigV4Request{}, &authError{http.StatusBadRequest, "InvalidRequest", "Missing required header for this request: x-amz-content-sha256"}
	}
	if req.payloadHash != unsignedPayload && !strings.HasPrefix(req.payloadHash, "STREAMING-") && !isHexSHA256(req.payloadHash) {
		return sigV4Request{}, &authError{http.StatusBadRequest, "InvalidArgument", "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-* or a hex SHA-256 digest"}
	}
	return req, nil
}

// parsePresignedQuery reads a presigned URL's X-Amz-* parameters.
func parsePresignedQuery(r *http.Request, query url.Values) (sigV4Request, error) {
	for _, name := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"} {
		if query.Get(name) == "" {
			return sigV4Request{}, malformedQuery("Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.")
		}
	}
	if query.Get("X-Amz-Algorithm") != sigV4Algorithm {
		return sigV4Request{}, malformedQuery("X-Amz-Algorithm only supports \"" + sigV4Algorithm + "\"")
	}
	expires, err := strconv.Atoi(query.Get("X-Amz-Expires"))
	if err != nil || expires < 0 {
		return sigV4Request{}, malformedQuery("X-Amz-Expires should be a number")
	}
	if expires > maxPresignSeconds {
		return sigV4Request{}, malformedQuery("X-Amz-Expires must be less than a week (in seconds) that is; the maximum expires is 604800 seconds")
	}
	// A presigned URL's body is unsigned unless it signs a digest.
	payloadHash := query.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = r.Header.Get("X-Amz-Content-Sha256")
	}
	if payloadHash == "" {
		payloadHash = unsignedPayload
	}
	return sigV4Request{
		credential:    query.Get("X-Amz-Credential"),
		signedHeaders: strings.Split(query.Get("X-Amz-SignedHeaders"), ";"),
		signature:     query.Get("X-Amz-Signature"),
		amzDate:       query.Get("X-Amz-Date"),
		payloadHash:   payloadHash,
		presigned:     true,
		expires:       expires,
	}, nil
}

func isHexSHA256(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == sha256.Size*2
}

// checkSignedHeaders requires SignedHeaders to be sorted, lowercase and
// unique, to include host, and to include every x-amz-* header sent, as S3
// does, so none of them can be added or changed without the key.
func checkSignedHeaders(r *http.Request, signed []string) error {
	seen := map[string]bool{}
	for i, name := range signed {
		if name == "" || name != strings.ToLower(name) || i > 0 && signed[i-1] >= name {
			return errSignatureMismatch
		}
		seen[name] = true
	}
	if !seen["host"] {
		return accessDenied("The host header must be signed.")
	}
	var unsigned []string
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") && !seen[lower] {
			unsigned = append(unsigned, lower)
		}
	}
	if len(unsigned) > 0 {
		sort.Strings(unsigned)
		return accessDenied("There were headers present in the request which were not signed: " + strings.Join(unsigned, ", "))
	}
	return nil
}

// canonicalRequest builds the request's canonical form, which the signature covers.
func canonicalRequest(r *http.Request, query url.Values, req sigV4Request) (string, error) {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	// S3 encodes the path once and doesn't normalize it.
	b.WriteString(uriEncode(r.URL.Path, false))
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(query, req.presigned))
	b.WriteByte('\n')
	for _, name := range req.signedHeaders {
		value, ok := headerValue(r, name)
		if !ok {
			return "", accessDenied("The request is missing the signed header " + name + ".")
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(strings.Join(req.signedHeaders, ";"))
	b.WriteByte('\n')
	b.WriteString(req.payloadHash)
	return b.String(), nil
}

// canonicalQuery encodes every parameter, sorted, leaving out a presigned
// URL's own signature.
func canonicalQuery(query url.Values, presigned bool) string {
	var pairs []string
	for name, values := range query {
		if presigned && name == "X-Amz-Signature" {
			continue
		}
		for _, value := range values {
			pairs = append(pairs, uriEncode(name, true)+"="+uriEncode(value, true))
		}
	}
	// Sorted by encoded name, then by encoded value.
	sort.Slice(pairs, func(i, j int) bool {
		ni, vi, _ := strings.Cut(pairs[i], "=")
		nj, vj, _ := strings.Cut(pairs[j], "=")
		if ni != nj {
			return ni < nj
		}
		return vi < vj
	})
	return strings.Join(pairs, "&")
}

// headerValue returns the canonical value of a signed header: its values
// joined with ",", each trimmed with inner runs of spaces collapsed.
func headerValue(r *http.Request, name string) (string, bool) {
	var values []string
	switch name {
	case "host":
		// net/http moves Host out of the header map.
		values = []string{r.Host}
	case "content-length":
		values = r.Header.Values(name)
		if len(values) == 0 && r.ContentLength >= 0 {
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		}
	default:
		values = r.Header.Values(name)
	}
	if len(values) == 0 || name == "host" && r.Host == "" {
		return "", false
	}
	for i, v := range values {
		values[i] = strings.Join(strings.Fields(v), " ")
	}
	return strings.Join(values, ","), true
}

// uriEncode percent-encodes every byte except A-Z, a-z, 0-9, '-', '.', '_'
// and '~', and '/' unless encodeSlash is set, with uppercase hex digits.
func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '/' && !encodeSlash {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

func stringToSign(amzDate, scope, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return sigV4Algorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
}

// sigV4Signature signs stringToSign with the key derived from secret for
// the date (yyyyMMdd) and region.
func sigV4Signature(secret, date, region, stringToSign string) []byte {
	key := hmacSHA256([]byte("AWS4"+secret), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, sigV4Service)
	key = hmacSHA256(key, sigV4Terminator)
	return hmacSHA256(key, stringToSign)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
