package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	defaults := options{addr: "127.0.0.1:8333", dir: "data", maxObjectBytes: defaultMaxObjectBytes}
	with := func(f func(*options)) options {
		o := defaults
		f(&o)
		return o
	}

	for _, tc := range []struct {
		name string
		args []string
		want options
	}{
		{"no arguments", nil, defaults},
		{"lone --", []string{"--"}, defaults},
		{"all long options", []string{"--addr", ":9000", "--dir=buckets", "--max-object-bytes", "1024"},
			with(func(o *options) { o.addr, o.dir, o.maxObjectBytes = ":9000", "buckets", 1024 })},
		{"value after =", []string{"--addr=0.0.0.0:80"},
			with(func(o *options) { o.addr = "0.0.0.0:80" })},
		{"only the first = splits", []string{"--dir=a=b"},
			with(func(o *options) { o.dir = "a=b" })},
		{"value starting with a dash", []string{"--dir", "-data"},
			with(func(o *options) { o.dir = "-data" })},
		{"value that looks like an option", []string{"--dir", "--help"},
			with(func(o *options) { o.dir = "--help" })},
		{"last occurrence wins", []string{"--dir", "a", "--dir", "b"},
			with(func(o *options) { o.dir = "b" })},
		{"-h", []string{"-h"}, with(func(o *options) { o.help = true })},
		{"--help", []string{"--help"}, with(func(o *options) { o.help = true })},
		{"repeated short flag", []string{"-hh"}, with(func(o *options) { o.help = true })},
		{"help alongside other options", []string{"--dir", "x", "-h"},
			with(func(o *options) { o.dir, o.help = "x", true })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArgs(tc.args)
			if err != nil {
				t.Fatalf("parseArgs(%q): %v", tc.args, err)
			}
			if got != tc.want {
				t.Fatalf("parseArgs(%q) = %+v, want %+v", tc.args, got, tc.want)
			}
		})
	}
}

func TestParseArgsErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-addr", ":9000"}, "unknown option -a"}, // single dash is a cluster of short booleans
		{[]string{"-dir=data"}, "unknown option -d"},
		{[]string{"-hx"}, "unknown option -x"},
		{[]string{"-H"}, "unknown option -H"},
		{[]string{"--addr"}, "option --addr requires a value"},
		{[]string{"--dir", "a", "--max-object-bytes"}, "option --max-object-bytes requires a value"},
		{[]string{"--addr="}, "option --addr requires a non-empty value"},
		{[]string{"--addr", ""}, "option --addr requires a non-empty value"},
		{[]string{"--dir="}, "option --dir requires a non-empty value"},
		{[]string{"--max-object-bytes="}, "option --max-object-bytes requires a non-empty value"},
		{[]string{"--nope=1"}, "unknown option --nope"},
		{[]string{"--Addr", ":9000"}, "unknown option --Addr"},
		{[]string{"--=x"}, "unknown option --"},
		{[]string{"--help=yes"}, "option --help does not take a value"},
		{[]string{"--max-object-bytes", "0"}, `positive integer, got "0"`},
		{[]string{"--max-object-bytes=-1"}, `positive integer, got "-1"`},
		{[]string{"--max-object-bytes=ten"}, `positive integer, got "ten"`},
		{[]string{"--max-object-bytes=1MB"}, `positive integer, got "1MB"`},
		{[]string{"--max-object-bytes=99999999999999999999"}, "positive integer"},
		{[]string{"extra"}, `unexpected argument "extra"`},
		{[]string{"-"}, `unexpected argument "-"`},
		{[]string{"--", "extra"}, `unexpected argument "extra"`},
		{[]string{"--dir", "data", "extra"}, `unexpected argument "extra"`},
	} {
		_, err := parseArgs(tc.args)
		if err == nil {
			t.Errorf("parseArgs(%q): expected an error", tc.args)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parseArgs(%q) error = %q, want it to contain %q", tc.args, err, tc.want)
		}
	}
}

func TestUsageListsEveryOption(t *testing.T) {
	for _, opt := range []string{"--addr", "--dir", "--max-object-bytes", "-h", "--help"} {
		if !strings.Contains(usage, opt) {
			t.Errorf("usage does not mention %s", opt)
		}
	}
}

func Example_parseArgs() {
	opts, _ := parseArgs([]string{"--addr", ":9000", "--dir=buckets"})
	fmt.Println(opts.addr, opts.dir)

	_, err := parseArgs([]string{"-addr", ":9000"})
	fmt.Println(err)
	// Output:
	// :9000 buckets
	// unknown option -a
}
