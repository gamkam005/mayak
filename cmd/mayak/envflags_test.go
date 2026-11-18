package main

import (
	"flag"
	"testing"
)

func TestEnvFlags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	link := fs.String("link", "", "")
	listen := fs.String("listen", "127.0.0.1:1080", "")
	state := fs.String("sub-state", "", "")
	open := fs.Bool("open", true, "")
	if err := fs.Parse([]string{"-listen", "1.2.3.4:5"}); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"MAYAK_LINK": "/etc/mayak/link.txt", "MAYAK_LISTEN": "0.0.0.0:1080", "MAYAK_SUB_STATE": "/data", "MAYAK_OPEN": "false"}
	if err := envFlags(fs, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	if *link != "/etc/mayak/link.txt" || *state != "/data" || *open {
		t.Fatalf("env not applied: %q %q %v", *link, *state, *open)
	}
	if *listen != "1.2.3.4:5" {
		t.Fatalf("command line must win, got %q", *listen)
	}
	if !flagSet(fs, "link") {
		t.Fatal("env flag must count as set")
	}
	env["MAYAK_OPEN"] = "maybe"
	fs2 := flag.NewFlagSet("t", flag.ContinueOnError)
	fs2.Bool("open", true, "")
	if err := envFlags(fs2, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err == nil {
		t.Fatal("want error for bad bool")
	}
}
