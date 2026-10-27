package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
)

// rebuildView renders the newest posts in const/items/ to view/index.html.
// The keys list newest first, so it's one LIST and a GET per post, in
// parallel. The view is a projection: it can always be rebuilt from const/,
// so it's written with a plain PUT by the one reader.
func (r *reader) rebuildView(ctx context.Context) error {
	keys, err := r.s3.list(ctx, itemsPrefix, r.viewSize)
	if err != nil {
		return err
	}
	entries := make([]entry, len(keys))
	errs := make([]error, len(keys))
	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Go(func() {
			resp, err := r.s3.get(ctx, key)
			if err == nil && resp.status != http.StatusOK {
				err = fmt.Errorf("%s vanished", key)
			}
			if err == nil {
				err = xml.Unmarshal(resp.body, &entries[i])
			}
			errs[i] = err
		})
	}
	wg.Wait()

	page := viewPage{Generated: r.now()}
	for i, e := range entries {
		if errs[i] != nil {
			return fmt.Errorf("%s: %w", keys[i], errs[i])
		}
		page.Posts = append(page.Posts, newViewPost(e))
	}
	var b bytes.Buffer
	if err := indexTemplate.Execute(&b, page); err != nil {
		return err
	}
	_, err = r.s3.put(ctx, indexKey, "text/html; charset=utf-8", b.Bytes(), "", "")
	return err
}

type viewPage struct {
	Generated time.Time
	Posts     []viewPost
}

type viewPost struct {
	Title, Link, Source, Snippet string
	Date                         time.Time
}

func newViewPost(e entry) viewPost {
	p := viewPost{Title: e.Title, Link: e.Link.Href, Source: e.Source.Title}
	if p.Title == "" {
		p.Title = "(untitled)"
	}
	if p.Source == "" {
		p.Source = e.Source.ID
	}
	p.Date, _ = time.Parse(time.RFC3339, firstNonEmpty(e.Published, e.Updated))
	for _, t := range []*atomText{e.Summary, e.Content} {
		if t != nil {
			p.Snippet = truncate(stripTags(t.Body), 280)
			break
		}
	}
	return p
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// html/template escapes every value and drops unsafe URLs such as
// javascript:, so a hostile feed can't inject markup into the page.
var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("Mon 2 Jan 2006, 15:04 UTC")
	},
	"iso": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
}).Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Latest posts</title>
<style>
body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem; color: #222; }
article { border-bottom: 1px solid #ddd; padding: 0.75rem 0; }
h2 { font-size: 1.05rem; margin: 0; }
a { color: #0645ad; text-decoration: none; }
.meta { color: #666; font-size: 0.85rem; }
p { margin: 0.25rem 0 0; }
footer { color: #888; font-size: 0.8rem; margin-top: 1rem; }
@media (prefers-color-scheme: dark) { body { background: #111; color: #ddd; } a { color: #8ab4f8; } article { border-color: #333; } }
</style>
<h1>Latest posts</h1>
{{range .Posts}}<article>
<h2>{{if .Link}}<a href="{{.Link}}">{{.Title}}</a>{{else}}{{.Title}}{{end}}</h2>
<div class="meta">{{.Source}}{{if not .Date.IsZero}} · <time datetime="{{iso .Date}}">{{date .Date}}</time>{{end}}</div>
{{with .Snippet}}<p>{{.}}</p>{{end}}
</article>
{{else}}<p>No posts yet.</p>
{{end}}<footer>Built {{date .Generated}} from const/items/ by rss-reader.</footer>
</html>
`))
