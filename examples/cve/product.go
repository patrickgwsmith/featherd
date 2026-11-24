package main

import (
	"regexp"
	"strings"
)

// A product's view picks the records that affect it, for a project with
// no CNA of its own. Most records name what they affect, in the CNA's
// affected entries, the ADPs' (CISA's adds CPEs) or their CPEs, but older
// MITRE records leave those "n/a" and say it only in the description, so
// a record whose CNA names nothing is matched on that instead.
type product struct {
	// named reports whether an affected entry or CPE is the product.
	named func(vendorProduct) bool
	// described matches a description that names the product with a
	// version, "SQLite before 3.32.3", rather than just mentioning it,
	// "the NGINX default configuration file".
	described *regexp.Regexp
}

func (p *product) matches(info recordInfo) bool {
	for _, vp := range info.Affected {
		if p.named(vp) {
			return true
		}
	}
	return info.Unnamed && p.described.MatchString(info.Description)
}

// vendorProduct is an affected entry's vendor and product, lowercased,
// with a CPE's underscores as spaces: {"f5", "nginx plus"}.
type vendorProduct struct{ Vendor, Product string }

func newVendorProduct(vendor, product string) vendorProduct {
	norm := func(s string) string {
		return strings.Join(strings.Fields(strings.ToLower(strings.ReplaceAll(s, "_", " "))), " ")
	}
	return vendorProduct{norm(vendor), norm(product)}
}

// cpeVendorProduct reads a CPE 2.3 name's vendor and product:
// cpe:2.3:a:sqlite:sqlite:3.32.0:*:….
func cpeVendorProduct(cpe string) (vendorProduct, bool) {
	f := strings.Split(cpe, ":")
	if len(f) < 5 || f[0] != "cpe" || f[1] != "2.3" {
		return vendorProduct{}, false
	}
	unescape := func(s string) string { return strings.ReplaceAll(s, `\`, "") }
	return newVendorProduct(unescape(f[3]), unescape(f[4])), true
}

// unnamed is a vendor or product that says nothing.
func unnamed(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "n/a", "na", "unknown", "[unknown]", "*", "-":
		return true
	}
	return false
}

// versioned matches a description naming one of names followed by a
// version, "before", "through" or "prior to", allowing an "(aka …)".
func versioned(names string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\b(?:` + names + `)(?: \(aka [^)]*\))? (?:v?[0-9]|before\b|through\b|prior to\b)`)
}

// SQLite: the library, its shell and extensions (FTS5, sqldiff), not
// the many wrappers named for it (sqlite3-ruby, ash_sqlite).
var sqliteProduct = &product{
	named: func(vp vendorProduct) bool {
		return vp.Vendor == "sqlite" || vp.Product == "sqlite" || vp.Product == "sqlite3"
	},
	described: versioned(`sqlite3?`),
}

// nginx: F5's NGINX products (Open Source, Plus, njs, Unit, the ingress
// controller and the rest), and older records' "nginx", but not others'
// tools named for it (nginx-ui, Nginx Proxy Manager, Kubernetes's
// ingress-nginx). F5 left some of its vendors "n/a" ("NGINX Controller").
var nginxProduct = &product{
	named: func(vp vendorProduct) bool {
		if unnamed(vp.Vendor) {
			return strings.HasPrefix(vp.Product, "nginx ") || vp.Product == "nginx"
		}
		switch vp.Vendor {
		case "f5", "f5, inc.", "f5 networks", "nginx", "nginx, inc.":
			return strings.HasPrefix(vp.Product, "nginx")
		}
		return vp.Product == "nginx"
	},
	described: versioned(`nginx(?: njs| unit)?|njs`),
}
