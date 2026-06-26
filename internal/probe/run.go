package probe

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/kayphoon/tunnelflux/internal/config"
)

func runMode(ctx context.Context, cfg config.Config, mode Mode) (Report, error) {
	items, err := candidates(cfg)
	if err != nil {
		return Report{}, err
	}
	if len(items) == 0 {
		return Report{}, errors.New("no candidate IPs")
	}
	timeout, err := time.ParseDuration(cfg.Edge.ProbeTimeout)
	if err != nil {
		return Report{}, err
	}
	rounds := cfg.Edge.ProbeRounds
	if rounds <= 0 {
		rounds = 5
	}
	concurrency := cfg.Edge.Concurrency
	if concurrency <= 0 {
		concurrency = 64
	}
	if mode == ModeQUIC && concurrency > 16 {
		concurrency = 16
	}

	jobs := make(chan string)
	results := make(chan Result, len(items))
	best := &probeBest{}
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results <- safeProbeIP(ctx, ip, cfg.Edge.Port, cfg.Edge.ServerName, mode, rounds, timeout, best)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range items {
			select {
			case <-ctx.Done():
				return
			case jobs <- ip:
			}
		}
	}()
	wg.Wait()
	close(results)

	var rows []Result
	for row := range results {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return better(rows[i], rows[j])
	})
	topN := cfg.Edge.TopN
	if topN <= 0 {
		topN = 4
	}
	top := uniqueTop(rows, topN)
	return Report{
		Mode:              string(mode),
		EffectiveProtocol: string(mode),
		Candidates:        len(items),
		Results:           rows,
		Top:               top,
	}, nil
}
