package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

func RunHTTP(ctx context.Context, target TargetInfo, ips ResolvedIPs) Result {
	start := time.Now()

	if len(ips.V4) == 0 && len(ips.V6) == 0 {
		return Result{
			Name:     "http",
			Status:   StatusSkipped,
			Summary:  "no DNS answers",
			Duration: time.Since(start),
			Details:  HTTPDetails{},
		}
	}

	var attempts []HTTPAttempt
	var mu sync.Mutex
	var wg sync.WaitGroup

	run := func(family, ip string) {
		defer wg.Done()
		a := runHTTP(ctx, target, family, ip)
		mu.Lock()
		attempts = append(attempts, a)
		mu.Unlock()
	}

	if len(ips.V4) > 0 {
		wg.Add(1)
		go run("ipv4", ips.V4[0])
	}
	if len(ips.V6) > 0 {
		wg.Add(1)
		go run("ipv6", ips.V6[0])
	}
	wg.Wait()

	// ipv4 first for stable output.
	for i := 0; i < len(attempts); i++ {
		for j := i + 1; j < len(attempts); j++ {
			if attempts[j].Family < attempts[i].Family {
				attempts[i], attempts[j] = attempts[j], attempts[i]
			}
		}
	}

	status := StatusFail
	switch {
	case allHTTPOK(attempts):
		status = StatusOK
	case anyHTTPOK(attempts):
		status = StatusWarn
	}

	return Result{
		Name:     "http",
		Status:   status,
		Summary:  summarizeHTTP(attempts),
		Duration: time.Since(start),
		Details:  HTTPDetails{Attempts: attempts},
	}
}

func runHTTP(ctx context.Context, target TargetInfo, family, ip string) HTTPAttempt {
	a := HTTPAttempt{Family: family, Address: net.JoinHostPort(ip, target.Port)}

	// Timing capture via httptrace. These fire for the request that starts on
	// this trace-context; Go will re-run them on redirected requests too, so we
	// capture timing for the FIRST hop only (which is what's diagnostically
	// interesting — subsequent hops may hit different hosts).
	var (
		reqStart   = time.Now()
		dnsStart   time.Time
		dnsDone    time.Time
		connStart  time.Time
		connDone   time.Time
		tlsStart   time.Time
		tlsDone    time.Time
		firstByte  time.Time
		timingOnce sync.Once
		t          HTTPTiming
	)
	finalizeTiming := func() {
		timingOnce.Do(func() {
			t.DNS = safeSub(dnsDone, dnsStart)
			t.Connect = safeSub(connDone, connStart)
			t.TLS = safeSub(tlsDone, tlsStart)
			t.TTFB = safeSub(firstByte, reqStart)
		})
	}

	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:         func(string, string) { connStart = time.Now() },
		ConnectDone:          func(string, string, error) { connDone = time.Now() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now(); finalizeTiming() },
	}

	// Pin the dialer to the pre-resolved IP so this attempt definitely uses
	// the family we say it does. We keep the original target.Host in the
	// request so Host header + TLS SNI remain correct.
	dialer := &net.Dialer{}
	network := "tcp4"
	if family == "ipv6" {
		network = "tcp6"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = target.Port
			}
			pinned := net.JoinHostPort(ip, port)
			return dialer.DialContext(ctx, network, pinned)
		},
		TLSClientConfig: &tls.Config{
			ServerName: target.Host,
		},
		ForceAttemptHTTP2:     true,
		DisableCompression:    false,
		MaxIdleConns:          2,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // rely on ctx
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.Response != nil {
				a.RedirectChain = append(a.RedirectChain, Redirect{
					From:   req.Response.Request.URL.String(),
					To:     req.URL.String(),
					Status: req.Response.StatusCode,
				})
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		"GET", target.Raw, nil,
	)
	if err != nil {
		a.Error = err.Error()
		return a
	}
	req.Header.Set("User-Agent", "netdoc/0.1 (+https://github.com/Jneville0815/netdoc)")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	total := time.Since(reqStart)
	finalizeTiming()
	t.Total = total
	a.Timing = t
	if err != nil {
		a.Error = err.Error()
		return a
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be closed cleanly and Content-Encoding
	// decompression (if any) actually happens. Cap read so we don't waste time
	// on huge bodies — we only need headers.
	_, _ = io.CopyN(io.Discard, resp.Body, 64*1024)

	a.FinalURL = resp.Request.URL.String()
	a.FinalStatus = resp.StatusCode
	a.Protocol = resp.Proto
	a.ContentEncoding = resp.Header.Get("Content-Encoding")
	a.ResponseHeaders = cloneHeaders(resp.Header)
	return a
}

func cloneHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func safeSub(end, start time.Time) time.Duration {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start)
}

func allHTTPOK(a []HTTPAttempt) bool {
	if len(a) == 0 {
		return false
	}
	for _, x := range a {
		if x.Error != "" || x.FinalStatus == 0 {
			return false
		}
	}
	return true
}

func anyHTTPOK(a []HTTPAttempt) bool {
	for _, x := range a {
		if x.Error == "" && x.FinalStatus != 0 {
			return true
		}
	}
	return false
}

func summarizeHTTP(a []HTTPAttempt) string {
	if len(a) == 0 {
		return "no attempts"
	}
	var parts []string
	for _, x := range a {
		if x.Error != "" {
			parts = append(parts, fmt.Sprintf("%s error: %s", x.Family, truncate(x.Error, 60)))
			continue
		}
		seg := fmt.Sprintf("%s %d %s in %s", x.Family, x.FinalStatus, x.Protocol, roundDur(x.Timing.Total))
		if len(x.RedirectChain) > 0 {
			seg += fmt.Sprintf(" (%d redirects)", len(x.RedirectChain))
		}
		parts = append(parts, seg)
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
