package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// s3Client speaks the small part of the S3 API the reader needs to featherd:
// path-style object PUT, GET, HEAD and DELETE with conditional headers,
// CreateBucket and ListObjectsV2. Requests are signed with SigV4 when a key
// pair is set, and sent unsigned otherwise, for FEATHERD_AUTH=none.
type s3Client struct {
	endpoint        *url.URL
	bucket          string
	accessKeyID     string
	secretAccessKey string
	region          string
	http            *http.Client
	now             func() time.Time
}

// s3Response is a response read in full: featherd's objects are small.
type s3Response struct {
	status int
	etag   string
	body   []byte
}

// s3Error is any status the caller didn't expect, with S3's error code.
type s3Error struct {
	method, key string
	status      int
	code        string
}

func (e *s3Error) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d %s", e.method, e.key, e.status, e.code)
}

func (c *s3Client) do(ctx context.Context, method, key string, query url.Values, body []byte, header http.Header) (*s3Response, error) {
	path := "/" + awsEscape(c.bucket, false)
	if key != "" {
		path += "/" + awsEscape(key, true)
	}
	rawQuery := canonicalQuery(query)
	// The URL is sent as written, so its path and query are exactly the ones
	// signed.
	target := c.endpoint.Scheme + "://" + c.endpoint.Host + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if c.accessKeyID != "" {
		c.sign(req, path, rawQuery, body)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &s3Response{status: resp.StatusCode, etag: resp.Header.Get("ETag"), body: data}, nil
}

// expect returns an s3Error unless the response's status is one of ok.
func expect(method, key string, resp *s3Response, ok ...int) error {
	for _, s := range ok {
		if resp.status == s {
			return nil
		}
	}
	var e struct {
		Code string `xml:"Code"`
	}
	xml.Unmarshal(resp.body, &e)
	return &s3Error{method: method, key: key, status: resp.status, code: e.Code}
}

func (c *s3Client) get(ctx context.Context, key string) (*s3Response, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return resp, expect("GET", key, resp, http.StatusOK, http.StatusNotFound)
}

// put stores body at key with one condition, such as If-None-Match: * or
// If-Match: "<etag>", or none for "", and returns 200 or 412.
func (c *s3Client) put(ctx context.Context, key, contentType string, body []byte, condition, value string) (*s3Response, error) {
	h := http.Header{"Content-Type": {contentType}}
	if condition != "" {
		h.Set(condition, value)
	}
	resp, err := c.do(ctx, http.MethodPut, key, nil, body, h)
	if err != nil {
		return nil, err
	}
	return resp, expect("PUT", key, resp, http.StatusOK, http.StatusPreconditionFailed)
}

func (c *s3Client) createBucket(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodPut, "", nil, nil, nil)
	if err != nil {
		return err
	}
	// 409 BucketAlreadyOwnedByYou: it already exists.
	return expect("PUT", "/"+c.bucket, resp, http.StatusOK, http.StatusConflict)
}

// list returns the keys under prefix in ascending order, at most limit of
// them, or all of them for limit 0.
func (c *s3Client) list(ctx context.Context, prefix string, limit int) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}}
		if limit > 0 {
			q.Set("max-keys", fmt.Sprint(min(limit-len(keys), 1000)))
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		if err := expect("LIST", prefix, resp, http.StatusOK); err != nil {
			return nil, err
		}
		var result struct {
			Contents []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
		}
		if err := xml.Unmarshal(resp.body, &result); err != nil {
			return nil, fmt.Errorf("LIST %s: %w", prefix, err)
		}
		for _, o := range result.Contents {
			keys = append(keys, o.Key)
		}
		if !result.IsTruncated || (limit > 0 && len(keys) >= limit) {
			return keys, nil
		}
		token = result.NextContinuationToken
	}
}

// sign adds a SigV4 Authorization header covering the host, the payload
// digest and the date, as featherd checks it.
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
func (c *s3Client) sign(req *http.Request, path, rawQuery string, body []byte) {
	now := c.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	payload := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payload)

	const signed = "host;x-amz-content-sha256;x-amz-date"
	canonical := strings.Join([]string{
		req.Method, path, rawQuery,
		"host:" + req.URL.Host,
		"x-amz-content-sha256:" + payload,
		"x-amz-date:" + amzDate,
		"", signed, payload,
	}, "\n")
	scope := now.Format("20060102") + "/" + c.region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	key := []byte("AWS4" + c.secretAccessKey)
	for _, part := range []string{now.Format("20060102"), c.region, "s3", "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%x",
		c.accessKeyID, scope, signed, hmacSHA256(key, toSign)))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// awsEscape percent-encodes s as SigV4 does: everything but A-Z, a-z, 0-9
// and -._~, plus / when keepSlash is set, as in object keys.
func awsEscape(s string, keepSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if 'A' <= ch && ch <= 'Z' || 'a' <= ch && ch <= 'z' || '0' <= ch && ch <= '9' ||
			strings.IndexByte("-._~", ch) >= 0 || keepSlash && ch == '/' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// canonicalQuery is the query string sorted and encoded as SigV4 requires.
// The request sends the same string, so the two can't differ.
func canonicalQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsEscape(k, false)+"="+awsEscape(v, false))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}
