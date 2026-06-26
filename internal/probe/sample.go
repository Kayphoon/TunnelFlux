package probe

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type probeBest struct {
	mu sync.RWMutex
	ms float64
}

func (b *probeBest) get() float64 {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ms
}

func (b *probeBest) observe(ms float64) {
	if b == nil || ms <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ms == 0 || ms < b.ms {
		b.ms = ms
	}
}

func safeProbeIP(ctx context.Context, ip string, port int, serverName string, mode Mode, rounds int, timeout time.Duration, best *probeBest) (result Result) {
	defer func() {
		if r := recover(); r != nil {
			result = summarize(nil)
			result.IP = ip
			result.Protocol = string(mode)
			result.OK = 0
			result.Fail = rounds
			result.When = time.Now().UTC()
			result.Errors = []string{fmt.Sprintf("probe panic: %v", r)}
			result.Score = score(result)
		}
	}()
	return probeIP(ctx, ip, port, serverName, mode, rounds, timeout, best)
}

func probeIP(ctx context.Context, ip string, port int, serverName string, mode Mode, rounds int, timeout time.Duration, best *probeBest) Result {
	var vals []float64
	errs := map[string]bool{}
	for i := 0; i < rounds; i++ {
		cutoff := best.get()
		var ms float64
		var err error
		switch mode {
		case ModeQUIC:
			ms, err = probeQUICFunc(ctx, ip, port, serverName, timeout)
		default:
			ms, err = probeTCPFunc(ctx, ip, port, timeout)
		}
		if err != nil {
			errs[shortErr(err)] = true
			break
		}
		vals = append(vals, ms)
		best.observe(ms)
		if cutoff > 0 && ms > cutoff {
			break
		}
	}
	result := summarize(vals)
	result.IP = ip
	result.Protocol = string(mode)
	result.OK = len(vals)
	result.Fail = rounds - len(vals)
	result.When = time.Now().UTC()
	for e := range errs {
		result.Errors = append(result.Errors, e)
	}
	sort.Strings(result.Errors)
	result.Score = score(result)
	return result
}

func shortErr(err error) string {
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}
