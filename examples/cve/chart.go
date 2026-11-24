package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

// The charts: each page has a line chart of how many CVEs were published
// on each of the last chartDays full days (UTC), by severity, and the kev
// page one of how many were added to the catalog. They're drawn as inline
// SVG when the page is written, so the pages stay static HTML.
//
// The pages list the newest new or updated CVEs, which can be a day's
// worth, so the charts are counted from an index of their own,
// mut/chart: one line per CVE published in the last chartKeep, with its
// severity and the vendor pages it's on. It's kept up as records are
// stored, so a CVE scored later, by an ADP, moves to its severity; built
// by a seed; and for a bucket that has none, backfilled once from the CVEs
// deltaLog.json lists as new.
const (
	chartKey  = "mut/chart"
	chartDays = 30
	// chartKeep is how long an entry is kept: the chart's days, today's,
	// and one more for any skew in datePublished.
	chartKeep = (chartDays + 2) * 24 * time.Hour
)

// chartLevels are the severities charted, in order. A CVSS score of 0
// ("none") is counted as low.
var chartLevels = []struct{ Level, Title string }{
	{"critical", "CRITICAL"}, {"high", "HIGH"}, {"medium", "MEDIUM"}, {"low", "LOW"}, {"", "unscored"},
}

type chartEntry struct {
	Published time.Time
	ID        string
	Level     string   // a chartLevels level
	Pages     []string // the vendors whose pages list it
	Gone      bool     // rejected, or no longer published, so it's dropped
}

func (e chartEntry) high() bool { return e.Level == "critical" || e.Level == "high" }

func chartLevel(level string) string {
	switch level {
	case "critical", "high", "medium", "low":
		return level
	case "none":
		return "low"
	}
	return ""
}

func encodeChart(es []chartEntry) []byte {
	var b bytes.Buffer
	for _, e := range es {
		level, pages := e.Level, strings.Join(e.Pages, ",")
		if level == "" {
			level = "-"
		}
		if pages == "" {
			pages = "-"
		}
		fmt.Fprintf(&b, "%s %s %s %s\n", e.Published.UTC().Format(time.RFC3339), e.ID, level, pages)
	}
	return b.Bytes()
}

func decodeChart(data []byte) []chartEntry {
	var es []chartEntry
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line)
		if len(f) != 4 || !cveIDRE.MatchString(f[1]) {
			continue
		}
		t, err := time.Parse(time.RFC3339, f[0])
		if err != nil {
			continue
		}
		e := chartEntry{Published: t, ID: f[1], Level: chartLevel(f[2])}
		if f[3] != "-" {
			e.Pages = strings.Split(f[3], ",")
		}
		es = append(es, e)
	}
	return es
}

// mergeChart applies changes to the index, dropping CVEs rejected and any
// published before since, and keeps it newest first.
func mergeChart(old []chartEntry, changes map[string]chartEntry, since time.Time) []chartEntry {
	byID := map[string]chartEntry{}
	for _, e := range old {
		byID[e.ID] = e
	}
	for id, e := range changes {
		byID[id] = e
	}
	out := make([]chartEntry, 0, len(byID))
	for _, e := range byID {
		if !e.Gone && !e.Published.Before(since) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Published.Equal(out[j].Published) {
			return out[i].Published.After(out[j].Published)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// chartChange is a stored record's entry, or nil if it doesn't belong in
// the index: it was published before since, or not at all.
func chartChange(info recordInfo, data []byte, since time.Time) *chartEntry {
	if info.ID == "" {
		return nil
	}
	if info.Rejected {
		return &chartEntry{ID: info.ID, Gone: true}
	}
	if info.Published.IsZero() || info.Published.Before(since) {
		return nil
	}
	c, err := newViewCVE(recentChange{CVEID: info.ID}, data)
	if err != nil {
		return nil
	}
	e := &chartEntry{Published: info.Published.UTC(), ID: info.ID, Level: chartLevel(c.Level)}
	for _, v := range vendorsFor(info) {
		e.Pages = append(e.Pages, v.Name)
	}
	return e
}

// writeChartIndex merges the records stored into mut/chart. A bucket with
// none yet is first backfilled from deltaLog.json at commit, unless commit
// is "" (a seed, whose changes are every record). It reports whether it
// backfilled, after which every page's chart is out of date.
func (s *syncer) writeChartIndex(ctx context.Context, commit string, vc *vendorChanges) (backfilled bool, err error) {
	resp, err := s.s3.get(ctx, chartKey)
	if err != nil {
		return false, err
	}
	var old []chartEntry
	changes := vc.chart
	if resp.status == http.StatusOK {
		old = decodeChart(resp.body)
	} else if commit != "" {
		s.log.Printf("chart index missing; backfilling from deltaLog.json")
		tmp, err := s.backfillChart(ctx, commit)
		if err != nil {
			return false, err
		}
		for id, e := range vc.chart {
			tmp[id] = e // stored this sync, so newer
		}
		changes, backfilled = tmp, true
	}
	idx := mergeChart(old, changes, s.now().Add(-chartKeep))
	if resp.status == http.StatusOK && len(idx) == len(old) && len(changes) == 0 {
		return false, nil // nothing added, changed or expired
	}
	_, err = s.s3.put(ctx, chartKey, "text/plain; charset=utf-8", encodeChart(idx), "", "")
	return backfilled, err
}

// backfillChart reads back the records deltaLog.json at commit lists as
// new, which are the CVEs published in its 30 days.
func (s *syncer) backfillChart(ctx context.Context, commit string) (map[string]chartEntry, error) {
	seen := map[string]bool{}
	var paths []string
	err := s.scanDeltaLog(ctx, commit, func(e delta, _ time.Time) bool {
		for _, c := range e.New {
			if p, ok := recordPath(c); ok && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	tmp := newVendorChanges()
	tmp.chartSince = s.now().Add(-chartKeep)
	if err := s.readBack(ctx, paths, tmp.add); err != nil {
		return nil, err
	}
	return tmp.chart, nil
}

// loadChart reads mut/chart, or nothing if there's none yet.
func (s *syncer) loadChart(ctx context.Context) ([]chartEntry, error) {
	resp, err := s.s3.get(ctx, chartKey)
	if err != nil || resp.status != http.StatusOK {
		return nil, err
	}
	return decodeChart(resp.body), nil
}

// chartData is one chart's counts: Days, oldest first, ending yesterday
// (UTC), as today's count isn't complete; and a series for each severity.
type chartData struct {
	Caption string
	Days    []time.Time
	Series  []chartSeries
}

type chartSeries struct {
	Key, Title string // Key picks its colour: a level, "total" or "kev"
	Counts     []int  // per day
}

func (s chartSeries) Sum() int {
	n := 0
	for _, c := range s.Counts {
		n += c
	}
	return n
}

func chartDaysTo(now time.Time) []time.Time {
	today := now.UTC().Truncate(24 * time.Hour)
	days := make([]time.Time, chartDays)
	for i := range days {
		days[i] = today.AddDate(0, 0, i-chartDays)
	}
	return days
}

// dayIndex is t's position in days, or -1.
func dayIndex(days []time.Time, t time.Time) int {
	i := int(t.UTC().Truncate(24*time.Hour).Sub(days[0]) / (24 * time.Hour))
	if t.Before(days[0]) || i >= len(days) {
		return -1
	}
	return i
}

// severityChart counts the entries keep picks by day and severity. Only the
// levels with any CVEs are drawn, and with more than one, their total too.
func severityChart(caption string, es []chartEntry, now time.Time, keep func(chartEntry) bool) *chartData {
	days := chartDaysTo(now)
	counts := map[string][]int{}
	for _, l := range chartLevels {
		counts[l.Level] = make([]int, len(days))
	}
	total := make([]int, len(days))
	for _, e := range es {
		if !keep(e) {
			continue
		}
		if i := dayIndex(days, e.Published); i >= 0 {
			counts[e.Level][i]++
			total[i]++
		}
	}
	c := &chartData{Caption: caption, Days: days}
	for _, l := range chartLevels {
		s := chartSeries{Key: l.Level, Title: l.Title, Counts: counts[l.Level]}
		if s.Key == "" {
			s.Key = "unscored"
		}
		if s.Sum() > 0 {
			c.Series = append(c.Series, s)
		}
	}
	if len(c.Series) != 1 {
		c.Series = append([]chartSeries{{Key: "total", Title: "total", Counts: total}}, c.Series...)
	}
	return c
}

func onPage(name string) func(chartEntry) bool {
	return func(e chartEntry) bool { return slices.Contains(e.Pages, name) }
}

// kevChart counts the catalog's entries by the day they were added.
func kevChart(entries []kevEntry, now time.Time) *chartData {
	days := chartDaysTo(now)
	counts := make([]int, len(days))
	for _, e := range entries {
		if t, err := time.Parse(time.DateOnly, e.DateAdded); err == nil {
			if i := dayIndex(days, t); i >= 0 {
				counts[i]++
			}
		}
	}
	return &chartData{
		Caption: "CVEs added to the catalog each day",
		Days:    days,
		Series:  []chartSeries{{Key: "kev", Title: "added", Counts: counts}},
	}
}

// The SVG's geometry, in its own units; it's scaled to the page's width.
const (
	chartW, chartH                       = 720.0, 170.0
	chartLeft, chartRight                = 34.0, 20.0
	chartTop, chartBottom                = 8.0, 22.0
	chartPlotW, chartPlotH               = chartW - chartLeft - chartRight, chartH - chartTop - chartBottom
	chartStep                            = chartPlotW / (chartDays - 1)
	chartTickTarget                      = 4
	chartLabelEvery                      = 7
	chartDayFormat, chartDayFormatTitled = "2 Jan", "Mon 2 Jan 2006"
)

// niceStep is the step between y gridlines for counts up to max: 1, 2 or
// 5 times a power of ten, giving at most chartTickTarget of them.
func niceStep(peak int) int {
	for step := 1; ; step *= 10 {
		for _, m := range []int{1, 2, 5} {
			if s := step * m; s*chartTickTarget >= peak {
				return s
			}
		}
	}
}

// HTML draws the chart as a figure with an inline SVG line chart, a
// tooltip for each day, and a legend with each series' 30-day total, as
// text so it's searchable.
func (c *chartData) HTML() template.HTML {
	esc := template.HTMLEscapeString
	peak := 0
	for _, s := range c.Series {
		peak = max(peak, slices.Max(s.Counts))
	}
	step := niceStep(max(peak, 1))
	top := step * ((max(peak, 1) + step - 1) / step)
	x := func(i int) float64 { return chartLeft + float64(i)*chartStep }
	y := func(n int) float64 { return chartTop + chartPlotH - float64(n)/float64(top)*chartPlotH }

	var b strings.Builder
	first, last := c.Days[0], c.Days[len(c.Days)-1]
	fmt.Fprintf(&b, `<figure class="chart"><figcaption>%s, %s to %s (UTC)</figcaption>`,
		esc(c.Caption), first.Format(chartDayFormat), last.Format(chartDayFormat))
	var summary []string
	for _, s := range c.Series {
		summary = append(summary, fmt.Sprintf("%d %s", s.Sum(), s.Title))
	}
	fmt.Fprintf(&b, `<svg viewBox="0 0 %g %g" role="img" aria-label="%s: %s">`,
		chartW, chartH, esc(c.Caption), esc(strings.Join(summary, ", ")))
	for n := 0; n <= top; n += step {
		fmt.Fprintf(&b, `<line class="grid" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/><text class="axis" x="%g" y="%.1f" text-anchor="end">%d</text>`,
			chartLeft, chartW-chartRight, y(n), y(n), chartLeft-6, y(n)+4, n)
	}
	for i := len(c.Days) - 1; i >= 0; i -= chartLabelEvery {
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%g" text-anchor="middle">%s</text>`, x(i), chartH-6, c.Days[i].Format(chartDayFormat))
	}
	// The total first, so the severities are drawn over it.
	for _, s := range c.Series {
		var pts []string
		for i, n := range s.Counts {
			pts = append(pts, fmt.Sprintf("%.1f,%.1f", x(i), y(n)))
		}
		fmt.Fprintf(&b, `<polyline class="s-%s" points="%s"/>`, s.Key, strings.Join(pts, " "))
	}
	for i, d := range c.Days {
		var parts []string
		for _, s := range c.Series {
			parts = append(parts, fmt.Sprintf("%d %s", s.Counts[i], s.Title))
		}
		fmt.Fprintf(&b, `<rect class="day" x="%.1f" y="%g" width="%.1f" height="%g"><title>%s: %s</title></rect>`,
			x(i)-chartStep/2, chartTop, chartStep, chartPlotH, d.Format(chartDayFormatTitled), esc(strings.Join(parts, ", ")))
	}
	b.WriteString(`</svg><ul class="legend">`)
	for _, s := range c.Series {
		fmt.Fprintf(&b, `<li><span class="key s-%s"></span>%s %d</li>`, s.Key, esc(s.Title), s.Sum())
	}
	b.WriteString(`</ul></figure>`)
	return template.HTML(b.String())
}
