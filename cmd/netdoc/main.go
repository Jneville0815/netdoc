package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jneville0815/netdoc/internal/probe"
	"github.com/Jneville0815/netdoc/internal/render"
)

func main() {
	var (
		raw     = flag.Bool("raw", false, "also print the full JSON probe bundle")
		timeout = flag.Int("timeout", 10, "per-probe timeout in seconds")
		noLLM   = flag.Bool("no-llm", false, "skip the LLM synthesis step")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: netdoc [flags] <url>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	target, err := probe.ParseTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	bundle := probe.RunAll(ctx, target, time.Duration(*timeout)*time.Second)

	render.Summary(os.Stdout, bundle)

	if !*noLLM {
		// LLM synthesis lands in a later milestone. For now just note it's skipped.
		fmt.Fprintln(os.Stdout, "(LLM synthesis not yet wired — re-run with --no-llm to silence this line)")
	}

	if *raw {
		render.Raw(os.Stdout, bundle)
	}
}
