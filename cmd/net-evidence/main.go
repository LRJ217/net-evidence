package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

func main() {
	os.Exit(run())
}

func run() int {
	timeout := flag.Duration("timeout", 20*time.Second, "overall diagnosis timeout")
	version := flag.Bool("version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: net-evidence [options] <URL|domain|host:port>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Output is raw local evidence; do not share it before redaction.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *version {
		fmt.Println(diagnostic.ToolVersion)
		return 0
	}
	if flag.NArg() != 1 || *timeout <= 0 {
		flag.Usage()
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := diagnostic.Run(ctx, flag.Arg(0), diagnostic.Options{TotalTimeout: *timeout})
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid target:", err)
		return 2
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode result:", err)
		return 1
	}
	return 0
}
