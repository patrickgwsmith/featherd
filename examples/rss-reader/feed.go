package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"strings"
	"time"
)

// entry is the one format every post is stored in: an Atom <entry> whose
// <source> names the feed it came from. RSS items and Atom entries are both
// converted to it, so const/items/ holds one format and the view reads one.
type entry struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2005/Atom entry"`
	ID        string      `xml:"id"`
	Title     string      `xml:"title"`
	Link      atomLink    `xml:"link"`
	Published string      `xml:"published,omitempty"`
	Updated   string      `xml:"updated"`
	Summary   *atomText   `xml:"summary"`
	Content   *atomText   `xml:"content"`
	Source    entrySource `xml:"source"`

	// sortTime orders the entry in const/items/. It isn't stored.
	sortTime time.Time
}

type entrySource struct {
	ID    string   `xml:"id"`
	Title string   `xml:"title"`
	Link  atomLink `xml:"link"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
}

type atomText struct {
	Type string `xml:"type,attr,omitempty"`
	Body string `xml:",chardata"`
}

// rawFeed decodes RSS 2.0 (<rss><channel>), RSS 1.0 (<rdf:RDF>, items
// beside the channel) and Atom (<feed>). encoding/xml matches tags without a
// namespace by local name, so atom:link in an RSS channel is seen as a link
// with an href and no text, and skipped.
type rawFeed struct {
	XMLName xml.Name
	Channel *struct {
		Title string    `xml:"title"`
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
	Items   []rssItem   `xml:"item"`
	Title   rawText     `xml:"title"`
	Entries []atomEntry `xml:"entry"`
}

type rssItem struct {
	Title       string    `xml:"title"`
	Links       []rssLink `xml:"link"`
	GUID        string    `xml:"guid"`
	PubDate     string    `xml:"pubDate"`
	DCDate      string    `xml:"http://purl.org/dc/elements/1.1/ date"`
	Description string    `xml:"description"`
	Content     string    `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
}

type rssLink struct {
	Href string `xml:"href,attr"`
	Text string `xml:",chardata"`
}

type atomEntry struct {
	ID        string     `xml:"id"`
	Title     rawText    `xml:"title"`
	Links     []atomLink `xml:"link"`
	Published string     `xml:"published"`
	Updated   string     `xml:"updated"`
	Summary   *rawText   `xml:"summary"`
	Content   *rawText   `xml:"content"`
}

// rawText is an Atom text construct as fetched: type="xhtml" content is
// markup, so it's kept as XML, while text and html are character data.
type rawText struct {
	Type  string `xml:"type,attr"`
	Body  string `xml:",chardata"`
	Inner string `xml:",innerxml"`
}

// parseFeed converts an RSS or Atom document fetched from feedURL to
// entries. now stands in for missing dates and caps future ones, so a
// misdated post can't stay at the top of the view.
func parseFeed(data []byte, feedURL string, now time.Time) (title string, entries []entry, err error) {
	var f rawFeed
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	d.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "iso-8859-1", "latin1", "windows-1252", "us-ascii":
			return latin1Reader{r}, nil
		}
		return nil, fmt.Errorf("unsupported charset %q", charset)
	}
	if err := d.Decode(&f); err != nil {
		return "", nil, fmt.Errorf("parsing feed: %w", err)
	}
	base, _ := url.Parse(feedURL)
	source := func(title string) entrySource {
		return entrySource{ID: feedURL, Title: strings.TrimSpace(title), Link: atomLink{Href: feedURL, Rel: "self"}}
	}

	switch f.XMLName.Local {
	case "rss", "RDF":
		items := f.Items
		if f.Channel != nil {
			title = f.Channel.Title
			items = append(items, f.Channel.Items...)
		}
		src := source(title)
		for _, it := range items {
			link := ""
			for _, l := range it.Links {
				if s := strings.TrimSpace(l.Text); s != "" {
					link = resolve(base, s)
					break
				}
			}
			e := entry{
				ID:     firstNonEmpty(strings.TrimSpace(it.GUID), link),
				Title:  strings.TrimSpace(it.Title),
				Link:   atomLink{Href: link, Rel: "alternate"},
				Source: src,
			}
			if s := strings.TrimSpace(it.Description); s != "" {
				e.Summary = &atomText{Type: "html", Body: s}
			}
			if s := strings.TrimSpace(it.Content); s != "" {
				e.Content = &atomText{Type: "html", Body: s}
			}
			e.setDates(parseDate(firstNonEmpty(it.PubDate, it.DCDate)), time.Time{}, now)
			entries = append(entries, e)
		}
	case "feed":
		title = f.Title.text()
		src := source(title)
		for _, ae := range f.Entries {
			link := ""
			for _, l := range ae.Links {
				if l.Rel == "" || l.Rel == "alternate" {
					link = resolve(base, l.Href)
					break
				}
			}
			e := entry{
				ID:      firstNonEmpty(strings.TrimSpace(ae.ID), link),
				Title:   ae.Title.text(),
				Link:    atomLink{Href: link, Rel: "alternate"},
				Summary: ae.Summary.asHTML(),
				Content: ae.Content.asHTML(),
				Source:  src,
			}
			e.setDates(parseDate(ae.Published), parseDate(ae.Updated), now)
			entries = append(entries, e)
		}
	default:
		return "", nil, fmt.Errorf("parsing feed: <%s> is neither RSS nor Atom", f.XMLName.Local)
	}

	// An entry with neither a GUID, an ID nor a link can't be recognised
	// next time, so it would be stored again on every change.
	kept := entries[:0]
	for _, e := range entries {
		if e.ID != "" {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 && len(entries) > 0 {
		return "", nil, errors.New("parsing feed: no entry has an ID or a link")
	}
	return strings.TrimSpace(title), kept, nil
}

// setDates fills Published and Updated, which Atom requires, and sortTime:
// the publication date, else the update date, else now, never after now.
func (e *entry) setDates(published, updated, now time.Time) {
	t := firstTime(published, updated, now)
	if t.After(now) {
		t = now
	}
	e.sortTime = t
	if !published.IsZero() {
		e.Published = published.UTC().Format(time.RFC3339)
	}
	e.Updated = firstTime(updated, published, now).UTC().Format(time.RFC3339)
}

// text returns an Atom text construct as plain text.
func (t rawText) text() string {
	switch t.Type {
	case "html":
		return stripTags(t.Body)
	case "xhtml":
		return stripTags(t.Inner)
	}
	return strings.Join(strings.Fields(t.Body), " ")
}

// asHTML returns an Atom text construct as HTML, the one form the stored
// entries use.
func (t *rawText) asHTML() *atomText {
	if t == nil {
		return nil
	}
	var s string
	switch t.Type {
	case "html":
		s = t.Body
	case "xhtml":
		s = t.Inner
	default:
		s = html.EscapeString(t.Body)
	}
	if s = strings.TrimSpace(s); s == "" {
		return nil
	}
	return &atomText{Type: "html", Body: s}
}

// latin1Reader decodes ISO-8859-1 to UTF-8. Windows-1252 differs only in
// 0x80–0x9F, which are rare enough in feeds to pass through as Latin-1.
type latin1Reader struct{ r io.Reader }

func (l latin1Reader) Read(p []byte) (int, error) {
	// Each byte becomes at most two, so read half as many.
	buf := make([]byte, max(len(p)/2, 1))
	n, err := l.r.Read(buf)
	out := p[:0]
	for _, b := range buf[:n] {
		if b < 0x80 {
			out = append(out, b)
		} else {
			out = append(out, 0xC0|b>>6, 0x80|b&0x3F)
		}
	}
	return len(out), err
}

// RSS dates are meant to be RFC 822, but feeds use many variants.
var dateLayouts = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC3339Nano,
	"Mon, 2 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 MST",
	"2 Jan 2006 15:04:05 -0700", "2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 2006 15:04 -0700", "Mon, 02 Jan 2006 15:04:05 Z",
	"2006-01-02T15:04:05", "2006-01-02",
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func resolve(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if base == nil {
		return ref
	}
	u, err := base.Parse(ref)
	if err != nil {
		return ref
	}
	return u.String()
}

// stripTags turns an HTML fragment into plain text, for titles and the
// view's snippets. Block tags become spaces and inline ones vanish, so
// "<p>a</p><p>b</p>" reads "a b" and "<b>a</b>." reads "a.". The page itself
// is escaped by html/template.
func stripTags(s string) string {
	var b strings.Builder
	for {
		start := strings.IndexByte(s, '<')
		if start < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:start])
		end := strings.IndexByte(s[start:], '>')
		if end < 0 {
			break
		}
		name := strings.ToLower(strings.TrimLeft(s[start+1:start+end], "/"))
		if i := strings.IndexAny(name, " \t\n/"); i >= 0 {
			name = name[:i]
		}
		if !inlineTags[name] {
			b.WriteByte(' ')
		}
		s = s[start+end+1:]
	}
	return strings.Join(strings.Fields(html.UnescapeString(b.String())), " ")
}

var inlineTags = map[string]bool{
	"a": true, "abbr": true, "b": true, "cite": true, "code": true, "em": true,
	"i": true, "kbd": true, "mark": true, "q": true, "s": true, "small": true,
	"span": true, "strong": true, "sub": true, "sup": true, "u": true,
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// parseSubscriptions returns the deduplicated xmlUrl of every <outline> in
// an OPML document, at any depth, in order.
func parseSubscriptions(data []byte) ([]string, error) {
	var urls []string
	seen := map[string]bool{}
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return urls, nil
			}
			return nil, fmt.Errorf("parsing OPML: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "outline" {
			continue
		}
		for _, a := range se.Attr {
			if a.Name.Local != "xmlUrl" {
				continue
			}
			u := strings.TrimSpace(a.Value)
			if (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) && !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}
}
