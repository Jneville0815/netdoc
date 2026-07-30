package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/fatih/color"
	"github.com/Jneville0815/netdoc/internal/probe"
)

// probeOrder controls the top-of-output summary strip.
var probeOrder = []string{"dns", "tcp", "tls", "http", "cdn", "env"}

// Summary prints the one-line-per-probe colored strip.
func Summary(w io.Writer, b probe.Bundle) {
	fmt.Fprintf(w, "%s  %s\n\n", color.New(color.Bold).Sprint("netdoc"), b.Target.Raw)

	keys := sortedProbeKeys(b.Results)
	for _, k := range keys {
		r := b.Results[k]
		dot := statusDot(r.Status)
		name := padRight(r.Name, 5)
		status := padRight(string(r.Status), 7)
		dur := fmt.Sprintf("(%s)", r.Duration.Round(time.Millisecond))
		fmt.Fprintf(w, "  %s %s %s %s %s\n", dot, name, status, r.Summary, color.New(color.Faint).Sprint(dur))
		if r.Error != "" {
			fmt.Fprintf(w, "       %s %s\n", color.New(color.Faint).Sprint("↳"), color.New(color.FgRed).Sprint(r.Error))
		}
	}
	fmt.Fprintln(w)
}

// Raw dumps the full bundle as indented JSON.
func Raw(w io.Writer, b probe.Bundle) {
	fmt.Fprintln(w, color.New(color.Faint).Sprint("─── raw bundle ───"))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(b)
}

func statusDot(s probe.Status) string {
	switch s {
	case probe.StatusOK:
		return color.New(color.FgGreen).Sprint("●")
	case probe.StatusWarn:
		return color.New(color.FgYellow).Sprint("●")
	case probe.StatusFail:
		return color.New(color.FgRed).Sprint("●")
	case probe.StatusSkipped:
		return color.New(color.Faint).Sprint("○")
	default:
		return "?"
	}
}

func sortedProbeKeys(results map[string]probe.Result) []string {
	order := map[string]int{}
	for i, k := range probeOrder {
		order[k] = i
	}
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, oj := order[keys[i]], order[keys[j]]
		if oi == 0 && keys[i] != probeOrder[0] {
			oi = len(probeOrder) + 1
		}
		if oj == 0 && keys[j] != probeOrder[0] {
			oj = len(probeOrder) + 1
		}
		if oi != oj {
			return oi < oj
		}
		return keys[i] < keys[j]
	})
	return keys
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + spaces(n-len(s))
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}
