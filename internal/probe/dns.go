package probe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var dnsResolvers = []struct {
	name, addr string
}{
	{"system", ""},
	{"1.1.1.1", "1.1.1.1:53"},
	{"8.8.8.8", "8.8.8.8:53"},
}

func RunDNS(ctx context.Context, target TargetInfo) Result {
	start := time.Now()

	type job struct{ resolver, recordType string }
	var jobs []job
	for _, r := range dnsResolvers {
		jobs = append(jobs, job{r.name, "A"}, job{r.name, "AAAA"})
	}

	queries := make([]DNSQuery, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			queries[i] = queryOne(ctx, j.resolver, j.recordType, target.Host)
		}(i, j)
	}
	wg.Wait()

	discrepancies := findDiscrepancies(queries)

	// Status: fail if nothing at all resolved; warn if resolvers disagree or
	// only one family resolved and it was an error on the other; otherwise ok.
	anySuccess := false
	anyAnswers := false
	for _, q := range queries {
		if q.Error == "" {
			anySuccess = true
			if len(q.Answers) > 0 {
				anyAnswers = true
			}
		}
	}
	var status Status
	var summary string
	switch {
	case !anySuccess:
		status = StatusFail
		if looksLikeNXDOMAIN(queries) {
			summary = "hostname does not resolve (NXDOMAIN / no such host)"
		} else {
			summary = "all resolvers errored"
		}
	case !anyAnswers:
		status = StatusFail
		summary = "no A or AAAA records returned"
	case len(discrepancies) > 0:
		status = StatusWarn
		summary = fmt.Sprintf("resolvers disagree (%d)", len(discrepancies))
	default:
		status = StatusOK
		summary = summarizeAnswers(queries)
	}

	return Result{
		Name:     "dns",
		Status:   status,
		Summary:  summary,
		Duration: time.Since(start),
		Details:  DNSDetails{Queries: queries, Discrepancies: discrepancies},
	}
}

func queryOne(ctx context.Context, resolverName, recordType, host string) (q DNSQuery) {
	q = DNSQuery{Resolver: resolverName, RecordType: recordType}
	start := time.Now()
	defer func() { q.Duration = time.Since(start) }()

	if resolverName == "system" {
		q = systemLookup(ctx, q, host)
		return
	}

	var qtype uint16
	switch recordType {
	case "A":
		qtype = dns.TypeA
	case "AAAA":
		qtype = dns.TypeAAAA
	default:
		q.Error = "unsupported record type"
		return
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	server, err := resolverAddr(resolverName)
	if err != nil {
		q.Error = err.Error()
		return
	}

	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	reply, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		q.Error = err.Error()
		return
	}
	if reply.Rcode != dns.RcodeSuccess {
		q.Error = dns.RcodeToString[reply.Rcode]
	}
	for _, rr := range reply.Answer {
		switch v := rr.(type) {
		case *dns.A:
			q.Answers = append(q.Answers, v.A.String())
		case *dns.AAAA:
			q.Answers = append(q.Answers, v.AAAA.String())
		}
	}
	sort.Strings(q.Answers)
	return
}

func systemLookup(ctx context.Context, q DNSQuery, host string) DNSQuery {
	network := "ip4"
	if q.RecordType == "AAAA" {
		network = "ip6"
	}
	addrs, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		q.Error = err.Error()
		return q
	}
	for _, a := range addrs {
		q.Answers = append(q.Answers, a.String())
	}
	sort.Strings(q.Answers)
	return q
}

func resolverAddr(name string) (string, error) {
	switch name {
	case "1.1.1.1":
		return "1.1.1.1:53", nil
	case "8.8.8.8":
		return "8.8.8.8:53", nil
	default:
		return "", fmt.Errorf("unknown resolver %q", name)
	}
}

func findDiscrepancies(queries []DNSQuery) []string {
	// Group answers by record type across resolvers; if the set of answers
	// differs between any two successful resolvers for the same type, flag it.
	byType := map[string]map[string][]string{} // recordType -> resolver -> sorted answers
	for _, q := range queries {
		if q.Error != "" {
			continue
		}
		if _, ok := byType[q.RecordType]; !ok {
			byType[q.RecordType] = map[string][]string{}
		}
		byType[q.RecordType][q.Resolver] = q.Answers
	}
	var out []string
	for rtype, perResolver := range byType {
		if len(perResolver) < 2 {
			continue
		}
		var ref string
		var refAnswers []string
		for res, ans := range perResolver {
			if ref == "" {
				ref, refAnswers = res, ans
				continue
			}
			if !stringSlicesEqual(ans, refAnswers) {
				out = append(out, fmt.Sprintf("%s/%s: %v vs %s/%s: %v",
					rtype, ref, refAnswers, rtype, res, ans))
			}
		}
	}
	sort.Strings(out)
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// looksLikeNXDOMAIN returns true if every query error points to name
// non-existence (NXDOMAIN from miekg, "no such host" from net.DefaultResolver).
func looksLikeNXDOMAIN(queries []DNSQuery) bool {
	any := false
	for _, q := range queries {
		if q.Error == "" {
			continue
		}
		any = true
		e := strings.ToLower(q.Error)
		if !strings.Contains(e, "nxdomain") && !strings.Contains(e, "no such host") {
			return false
		}
	}
	return any
}

func summarizeAnswers(queries []DNSQuery) string {
	// Prefer system resolver's answers for the summary; fall back to any.
	var a4, a6 []string
	for _, q := range queries {
		if q.Error != "" || len(q.Answers) == 0 {
			continue
		}
		if q.Resolver == "system" {
			switch q.RecordType {
			case "A":
				a4 = q.Answers
			case "AAAA":
				a6 = q.Answers
			}
		}
	}
	if len(a4) == 0 && len(a6) == 0 {
		for _, q := range queries {
			if q.Error != "" {
				continue
			}
			if len(a4) == 0 && q.RecordType == "A" {
				a4 = q.Answers
			}
			if len(a6) == 0 && q.RecordType == "AAAA" {
				a6 = q.Answers
			}
		}
	}
	var parts []string
	if len(a4) > 0 {
		parts = append(parts, "A="+strings.Join(a4, ","))
	}
	if len(a6) > 0 {
		parts = append(parts, "AAAA="+strings.Join(a6, ","))
	}
	if len(parts) == 0 {
		return "no answers"
	}
	return strings.Join(parts, " ")
}
