package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

func RunTCP(ctx context.Context, target TargetInfo, ips ResolvedIPs) Result {
	start := time.Now()

	if len(ips.V4) == 0 && len(ips.V6) == 0 {
		return Result{
			Name:     "tcp",
			Status:   StatusSkipped,
			Summary:  "no DNS answers to dial",
			Duration: time.Since(start),
			Details:  TCPDetails{},
		}
	}

	var attempts []TCPAttempt
	var mu sync.Mutex
	var wg sync.WaitGroup

	dial := func(family, ip string) {
		defer wg.Done()
		a := tryDial(ctx, family, ip, target.Port)
		mu.Lock()
		attempts = append(attempts, a)
		mu.Unlock()
	}

	if len(ips.V4) > 0 {
		wg.Add(1)
		go dial("ipv4", ips.V4[0])
	}
	if len(ips.V6) > 0 {
		wg.Add(1)
		go dial("ipv6", ips.V6[0])
	}
	wg.Wait()

	// Stable order: ipv4 first.
	sortAttempts(attempts)

	// Status aggregation.
	anySuccess := false
	allFail := true
	for _, a := range attempts {
		if a.Success {
			anySuccess = true
			allFail = false
		} else {
			// A single family failing while another works is a warn, not fail.
		}
	}
	if !allFail {
		_ = anySuccess
	}
	status := StatusFail
	var summary string
	switch {
	case allSucceeded(attempts):
		status = StatusOK
		summary = summarizeTCP(attempts)
	case anyFailed(attempts) && anySucceededSlice(attempts):
		status = StatusWarn
		summary = summarizeTCP(attempts)
	default:
		status = StatusFail
		summary = summarizeTCP(attempts)
	}

	return Result{
		Name:     "tcp",
		Status:   status,
		Summary:  summary,
		Duration: time.Since(start),
		Details:  TCPDetails{Attempts: attempts},
	}
}

func tryDial(ctx context.Context, family, ip, port string) TCPAttempt {
	addr := net.JoinHostPort(ip, port)
	a := TCPAttempt{Address: addr, Family: family}
	start := time.Now()
	d := net.Dialer{}
	network := "tcp4"
	if family == "ipv6" {
		network = "tcp6"
	}
	conn, err := d.DialContext(ctx, network, addr)
	a.ConnectTime = time.Since(start)
	if err != nil {
		a.Success = false
		a.Error = err.Error()
		a.FailureMode = classifyDialError(err)
		return a
	}
	_ = conn.Close()
	a.Success = true
	return a
}

func classifyDialError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	}
	// Last-resort string sniff; syscall errors are usually wrapped cleanly on
	// darwin but belt-and-braces for weird cases.
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "reset"):
		return "reset"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	case strings.Contains(s, "timeout"), strings.Contains(s, "timed out"):
		return "timeout"
	}
	return "other"
}

func sortAttempts(a []TCPAttempt) {
	// ipv4 before ipv6 for readable output.
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j].Family < a[i].Family {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}

func allSucceeded(a []TCPAttempt) bool {
	if len(a) == 0 {
		return false
	}
	for _, x := range a {
		if !x.Success {
			return false
		}
	}
	return true
}

func anyFailed(a []TCPAttempt) bool {
	for _, x := range a {
		if !x.Success {
			return true
		}
	}
	return false
}

func anySucceededSlice(a []TCPAttempt) bool {
	for _, x := range a {
		if x.Success {
			return true
		}
	}
	return false
}

func summarizeTCP(a []TCPAttempt) string {
	if len(a) == 0 {
		return "no attempts"
	}
	var parts []string
	for _, x := range a {
		if x.Success {
			parts = append(parts, fmt.Sprintf("%s→%s in %s", x.Family, x.Address, roundDur(x.ConnectTime)))
		} else {
			parts = append(parts, fmt.Sprintf("%s→%s %s", x.Family, x.Address, x.FailureMode))
		}
	}
	return strings.Join(parts, ", ")
}

func roundDur(d time.Duration) time.Duration {
	return d.Round(time.Millisecond)
}
