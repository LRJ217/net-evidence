package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/history"
	"github.com/LRJ217/net-evidence/internal/share"
	"golang.org/x/net/publicsuffix"
)

type ObservationSample struct {
	RunID        string           `json:"run_id"`
	Number       int              `json:"number"`
	StartedAt    time.Time        `json:"started_at"`
	Outcome      string           `json:"outcome"`
	FailureLayer string           `json:"failure_layer,omitempty"`
	DurationMs   int64            `json:"duration_ms"`
	Saved        *history.Summary `json:"saved,omitempty"`
	HistoryError bool             `json:"history_error,omitempty"`
}

type ObservationComplete struct {
	RunID         string `json:"run_id"`
	Samples       int    `json:"samples"`
	Successes     int    `json:"successes"`
	Failures      int    `json:"failures"`
	HistoryErrors int    `json:"history_errors"`
	Cancelled     bool   `json:"cancelled"`
	Error         string `json:"error,omitempty"`
}

func (s *Service) StartObservation(input string, timeoutSeconds, intervalSeconds, durationMinutes int) (string, error) {
	if _, err := diagnostic.NormalizeTarget(input); err != nil {
		return "", err
	}
	if timeoutSeconds < 5 || timeoutSeconds > 60 {
		return "", fmt.Errorf("timeout must be between 5 and 60 seconds")
	}
	if intervalSeconds != 10 && intervalSeconds != 30 && intervalSeconds != 60 {
		return "", fmt.Errorf("unsupported sampling interval")
	}
	if durationMinutes != 5 && durationMinutes != 10 && durationMinutes != 30 {
		return "", fmt.Errorf("unsupported sampling duration")
	}
	id, ctx, err := s.begin()
	if err != nil {
		return "", err
	}
	go func() {
		bounded, cancel := context.WithTimeout(ctx, time.Duration(durationMinutes)*time.Minute)
		defer cancel()
		s.observe(bounded, id, input, time.Duration(timeoutSeconds)*time.Second,
			time.Duration(intervalSeconds)*time.Second, durationMinutes*60/intervalSeconds)
	}()
	return id, nil
}

func (s *Service) observe(ctx context.Context, id, input string, timeout, interval time.Duration, maxSamples int) {
	complete := ObservationComplete{RunID: id}
	defer func() {
		complete.Cancelled = errors.Is(ctx.Err(), context.Canceled)
		s.finish(id)
		s.send("observation:complete", complete)
	}()
	savedSuccess := false
	for number := 1; number <= maxSamples && ctx.Err() == nil; number++ {
		started := time.Now()
		result, err := s.run(ctx, input, diagnostic.Options{
			TotalTimeout: timeout, HTTPTimeout: timeout, ProbeSystemProxy: true,
		})
		if err != nil {
			complete.Error = "诊断引擎未能完成采样"
			return
		}
		outcome := history.Outcome(result)
		sample := ObservationSample{RunID: id, Number: number, StartedAt: started.UTC(),
			Outcome: outcome, FailureLayer: failureLayer(result), DurationMs: result.DurationMs}
		if ctx.Err() != nil {
			sample.FailureLayer = ""
		}
		complete.Samples++
		if outcome == "success" {
			complete.Successes++
		} else {
			complete.Failures++
		}
		if ctx.Err() == nil && (outcome != "success" || !savedSuccess) {
			summary, saveErr := s.store.Save(result)
			if saveErr != nil {
				sample.HistoryError = true
				complete.HistoryErrors++
			} else {
				sample.Saved = &summary
				if outcome == "success" {
					savedSuccess = true
				}
			}
		}
		s.send("observation:sample", sample)
		if number == maxSamples {
			return
		}
		wait := time.Until(started.Add(interval))
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func failureLayer(r diagnostic.Result) string {
	for _, step := range []struct {
		id     string
		status diagnostic.Status
	}{{"dns", r.DNS.Status}, {"tcp", r.TCP.Status}, {"tls", r.TLS.Status}, {"http", r.HTTP.Status}} {
		if step.status == diagnostic.StatusFailure {
			return step.id
		}
	}
	if r.HTTP.Data != nil && r.HTTP.Data.StatusCode >= 400 {
		return "http"
	}
	if r.ProxyHTTP != nil && r.ProxyHTTP.Status == diagnostic.StatusFailure {
		return "proxy_http"
	}
	return ""
}

type VariantResult struct {
	RunID        string            `json:"run_id"`
	URL          string            `json:"url"`
	Outcome      string            `json:"outcome"`
	DNS          diagnostic.Status `json:"dns"`
	TCP          diagnostic.Status `json:"tcp"`
	TLS          diagnostic.Status `json:"tls"`
	HTTP         diagnostic.Status `json:"http"`
	HTTPCode     int               `json:"http_code"`
	FinalURL     string            `json:"final_url,omitempty"`
	FailureLayer string            `json:"failure_layer,omitempty"`
	DurationMs   int64             `json:"duration_ms"`
}

type VariantsComplete struct {
	RunID     string `json:"run_id"`
	Cancelled bool   `json:"cancelled"`
}

func (s *Service) StartVariants(input string, timeoutSeconds int) (string, error) {
	urls, err := variantURLs(input)
	if err != nil {
		return "", err
	}
	if timeoutSeconds < 5 || timeoutSeconds > 60 {
		return "", fmt.Errorf("timeout must be between 5 and 60 seconds")
	}
	id, ctx, err := s.begin()
	if err != nil {
		return "", err
	}
	go s.checkVariants(ctx, id, urls, time.Duration(timeoutSeconds)*time.Second)
	return id, nil
}

func variantURLs(input string) ([]string, error) {
	target, err := diagnostic.NormalizeTarget(input)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(target.Host) != nil ||
		(target.Scheme == "http" && target.Port != "80") ||
		(target.Scheme == "https" && target.Port != "443") {
		return nil, fmt.Errorf("entry comparison requires a domain on its standard HTTP or HTTPS port")
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(target.Host)
	if err != nil || strings.TrimPrefix(target.Host, "www.") != base {
		return nil, fmt.Errorf("entry comparison requires a root domain or its www host")
	}
	return []string{"http://" + base + "/", "https://" + base + "/",
		"http://www." + base + "/", "https://www." + base + "/"}, nil
}

func (s *Service) checkVariants(ctx context.Context, id string, urls []string, timeout time.Duration) {
	var workers sync.WaitGroup
	for _, variantURL := range urls {
		workers.Add(1)
		go func(variantURL string) {
			defer workers.Done()
			if ctx.Err() != nil {
				return
			}
			result, err := s.run(ctx, variantURL, diagnostic.Options{
				TotalTimeout: timeout, HTTPTimeout: timeout, ProbeSystemProxy: true,
			})
			row := VariantResult{RunID: id, URL: variantURL, Outcome: "partial",
				DNS: diagnostic.StatusSkipped, TCP: diagnostic.StatusSkipped,
				TLS: diagnostic.StatusSkipped, HTTP: diagnostic.StatusSkipped}
			if err == nil {
				row.Outcome = history.Outcome(result)
				row.DNS, row.TCP, row.TLS, row.HTTP = result.DNS.Status, result.TCP.Status, result.TLS.Status, result.HTTP.Status
				row.FailureLayer, row.DurationMs = failureLayer(result), result.DurationMs
				if safe := share.Build(result).Evidence.HTTP.Data; safe != nil {
					row.HTTPCode, row.FinalURL = safe.StatusCode, safe.FinalURL
				}
			}
			s.send("variants:result", row)
		}(variantURL)
	}
	workers.Wait()
	s.finish(id)
	s.send("variants:complete", VariantsComplete{RunID: id, Cancelled: errors.Is(ctx.Err(), context.Canceled)})
}
