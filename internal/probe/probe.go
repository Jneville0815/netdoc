package probe

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

type Result struct {
	Name     string        `json:"name"`
	Status   Status        `json:"status"`
	Summary  string        `json:"summary"`
	Duration time.Duration `json:"duration_ns"`
	Error    string        `json:"error,omitempty"`
	Details  any           `json:"details,omitempty"`
}

type Bundle struct {
	Target   TargetInfo        `json:"target"`
	RunAt    time.Time         `json:"run_at"`
	Duration time.Duration     `json:"duration_ns"`
	Results  map[string]Result `json:"results"`
}

type TargetInfo struct {
	Raw    string `json:"raw"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	Path   string `json:"path"`
}

func (t TargetInfo) HostPort() string {
	return t.Host + ":" + t.Port
}

// ParseTarget accepts bare hostnames, host:port, or full URLs. Bare hostnames
// default to https://.
func ParseTarget(s string) (TargetInfo, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return TargetInfo{}, fmt.Errorf("empty target")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return TargetInfo{}, fmt.Errorf("parse url: %w", err)
	}
	if u.Host == "" {
		return TargetInfo{}, fmt.Errorf("no host in %q", s)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return TargetInfo{}, fmt.Errorf("unsupported scheme %q (want http or https)", u.Scheme)
		}
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return TargetInfo{
		Raw:    s,
		Scheme: u.Scheme,
		Host:   host,
		Port:   port,
		Path:   path,
	}, nil
}

// ResolvedIPs is the DNS output the later probes care about: the de-duplicated
// union of addresses seen across all resolvers, split by family.
type ResolvedIPs struct {
	V4 []string
	V6 []string
}

// RunAll executes the full probe pipeline. Phase 1 runs DNS alone (later probes
// need its output). Phase 2 fans TCP and HTTP out in parallel. Timeout is a
// per-probe cap, not a total-run cap.
func RunAll(ctx context.Context, target TargetInfo, perProbeTimeout time.Duration) Bundle {
	start := time.Now()
	bundle := Bundle{
		Target:  target,
		RunAt:   start,
		Results: map[string]Result{},
	}

	dnsCtx, cancel := context.WithTimeout(ctx, perProbeTimeout)
	dnsRes := RunDNS(dnsCtx, target)
	cancel()
	bundle.Results["dns"] = dnsRes
	ips := extractIPs(dnsRes)

	var wg sync.WaitGroup
	var tcpRes, httpRes Result

	wg.Add(2)
	go func() {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, perProbeTimeout)
		defer cancel()
		tcpRes = RunTCP(c, target, ips)
	}()
	go func() {
		defer wg.Done()
		c, cancel := context.WithTimeout(ctx, perProbeTimeout)
		defer cancel()
		httpRes = RunHTTP(c, target, ips)
	}()
	wg.Wait()

	bundle.Results["tcp"] = tcpRes
	bundle.Results["http"] = httpRes
	bundle.Duration = time.Since(start)
	return bundle
}

func extractIPs(dns Result) ResolvedIPs {
	d, ok := dns.Details.(DNSDetails)
	if !ok {
		return ResolvedIPs{}
	}
	seenV4 := map[string]bool{}
	seenV6 := map[string]bool{}
	out := ResolvedIPs{}
	for _, q := range d.Queries {
		for _, a := range q.Answers {
			switch q.RecordType {
			case "A":
				if !seenV4[a] {
					seenV4[a] = true
					out.V4 = append(out.V4, a)
				}
			case "AAAA":
				if !seenV6[a] {
					seenV6[a] = true
					out.V6 = append(out.V6, a)
				}
			}
		}
	}
	return out
}

// ---- Per-probe Details ----

type DNSDetails struct {
	Queries       []DNSQuery `json:"queries"`
	Discrepancies []string   `json:"discrepancies,omitempty"`
}

type DNSQuery struct {
	Resolver   string        `json:"resolver"`
	RecordType string        `json:"record_type"`
	Answers    []string      `json:"answers"`
	Duration   time.Duration `json:"duration_ns"`
	Error      string        `json:"error,omitempty"`
}

type TCPDetails struct {
	Attempts []TCPAttempt `json:"attempts"`
}

type TCPAttempt struct {
	Address     string        `json:"address"`
	Family      string        `json:"family"`
	ConnectTime time.Duration `json:"connect_time_ns"`
	Success     bool          `json:"success"`
	FailureMode string        `json:"failure_mode,omitempty"`
	Error       string        `json:"error,omitempty"`
}

type HTTPDetails struct {
	Attempts []HTTPAttempt `json:"attempts"`
}

type HTTPAttempt struct {
	Family          string              `json:"family"`
	Address         string              `json:"address"`
	FinalURL        string              `json:"final_url,omitempty"`
	FinalStatus     int                 `json:"final_status,omitempty"`
	Protocol        string              `json:"protocol,omitempty"`
	ContentEncoding string              `json:"content_encoding,omitempty"`
	RedirectChain   []Redirect          `json:"redirect_chain,omitempty"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
	Timing          HTTPTiming          `json:"timing"`
	Error           string              `json:"error,omitempty"`
}

type Redirect struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Status int    `json:"status"`
}

type HTTPTiming struct {
	DNS     time.Duration `json:"dns_ns"`
	Connect time.Duration `json:"connect_ns"`
	TLS     time.Duration `json:"tls_ns"`
	TTFB    time.Duration `json:"ttfb_ns"`
	Total   time.Duration `json:"total_ns"`
}
