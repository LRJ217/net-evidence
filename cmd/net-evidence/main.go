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
	"github.com/LRJ217/net-evidence/internal/share"
)

func main() {
	os.Exit(run())
}

func run() int {
	timeout := flag.Duration("timeout", 20*time.Second, "overall diagnosis timeout")
	format := flag.String("format", "json", "output format: json (redacted), html, issue, raw-json")
	outPath := flag.String("out", "", "write to a new file instead of stdout (never overwrites)")
	version := flag.Bool("version", false, "print version")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: net-evidence [options] <URL|domain|host:port>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Default output is redacted JSON; use -format raw-json only for local evidence.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *version {
		fmt.Println(diagnostic.ToolVersion)
		return 0
	}
	if flag.NArg() != 1 || *timeout <= 0 || (*format != "raw-json" && *format != "json" && *format != "html" && *format != "issue") {
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
	var data []byte
	if *format == "raw-json" {
		data, err = json.MarshalIndent(result, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	} else {
		report := share.Build(result)
		switch *format {
		case "json":
			data, err = share.RenderJSON(report)
		case "html":
			data, err = share.RenderHTML(report)
		case "issue":
			data = share.RenderIssue(report)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "render result:", err)
		return 1
	}
	if *outPath == "" {
		if _, err = os.Stdout.Write(data); err != nil {
			fmt.Fprintln(os.Stderr, "write result:", err)
			return 1
		}
		return 0
	}
	file, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create output:", err)
		return 1
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		fmt.Fprintln(os.Stderr, "write output:", writeErr, closeErr)
		return 1
	}
	return 0
}
