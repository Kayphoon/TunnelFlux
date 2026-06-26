package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUniqueTop(t *testing.T) {
	rows := []Result{
		{IP: "1.1.1.1", OK: 3, MedianMS: 1, Score: 1},
		{IP: "1.1.1.1", OK: 3, MedianMS: 2, Score: 2},
		{IP: "1.1.1.2", OK: 3, MedianMS: 2, Score: 2},
		{IP: "1.1.1.3", OK: 0, MedianMS: 0, Score: 0},
	}
	top := uniqueTop(rows, 2)
	if len(top) != 2 {
		t.Fatalf("len=%d", len(top))
	}
	if top[0].IP != "1.1.1.1" || top[1].IP != "1.1.1.2" {
		t.Fatalf("unexpected top: %+v", top)
	}
}

func TestQUICServerNameUsesCloudflaredEdgeName(t *testing.T) {
	if got := quicServerName(""); got != "quic.cftunnel.com" {
		t.Fatalf("empty server name = %q", got)
	}
	if got := quicServerName("region1.v2.argotunnel.com"); got != "quic.cftunnel.com" {
		t.Fatalf("legacy region server name = %q", got)
	}
	if got := quicServerName("custom.example.com"); got != "custom.example.com" {
		t.Fatalf("custom server name = %q", got)
	}
}

func TestProbeIPStopsWhenSampleExceedsBest(t *testing.T) {
	old := probeQUICFunc
	defer func() { probeQUICFunc = old }()

	calls := 0
	probeQUICFunc = func(context.Context, string, int, string, time.Duration) (float64, error) {
		calls++
		return 12, nil
	}

	best := &probeBest{}
	best.observe(9)
	got := probeIP(context.Background(), "198.41.1.1", 7844, "quic.cftunnel.com", ModeQUIC, 8, time.Second, best)
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if got.OK != 1 || got.Fail != 7 {
		t.Fatalf("result = %+v, want one successful early-stopped sample", got)
	}
}

func TestProbeIPStopsAfterFirstError(t *testing.T) {
	old := probeQUICFunc
	defer func() { probeQUICFunc = old }()

	calls := 0
	probeQUICFunc = func(context.Context, string, int, string, time.Duration) (float64, error) {
		calls++
		return 0, errors.New("timeout")
	}

	got := probeIP(context.Background(), "198.41.1.1", 7844, "quic.cftunnel.com", ModeQUIC, 8, time.Second, &probeBest{})
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if got.OK != 0 || got.Fail != 8 {
		t.Fatalf("result = %+v, want failed early-stopped probe", got)
	}
}
