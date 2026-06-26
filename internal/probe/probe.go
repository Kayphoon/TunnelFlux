package probe

import (
	"context"
	"errors"
	"time"

	"github.com/kayphoon/tunnelflux/internal/config"
)

type Mode string

const (
	ModeAuto  Mode = config.ProtocolAuto
	ModeQUIC  Mode = config.ProtocolQUIC
	ModeHTTP2 Mode = config.ProtocolHTTP2
)

type Result struct {
	IP       string    `json:"ip"`
	Protocol string    `json:"protocol"`
	OK       int       `json:"ok"`
	Fail     int       `json:"fail"`
	MedianMS float64   `json:"median_ms"`
	MeanMS   float64   `json:"mean_ms"`
	MinMS    float64   `json:"min_ms"`
	MaxMS    float64   `json:"max_ms"`
	StdevMS  float64   `json:"stdev_ms"`
	Score    float64   `json:"score"`
	Errors   []string  `json:"errors,omitempty"`
	When     time.Time `json:"when"`
}

type Report struct {
	Mode              string   `json:"mode"`
	EffectiveProtocol string   `json:"effective_protocol"`
	Candidates        int      `json:"candidates"`
	Results           []Result `json:"results"`
	Top               []Result `json:"top"`
}

var (
	probeQUICFunc = probeQUIC
	probeTCPFunc  = probeTCP
)

func Run(ctx context.Context, cfg config.Config, mode Mode) (Report, error) {
	cfg = cfg.WithDefaults()
	if mode == "" {
		mode = Mode(cfg.Cloudflared.Protocol)
	}
	if mode == ModeAuto || mode == ModeQUIC {
		rep, err := runMode(ctx, cfg, ModeQUIC)
		if err == nil && len(rep.Top) >= minTop(cfg.Edge.TopN, len(cfg.Edge.Hostnames)) {
			rep.Mode = string(mode)
			rep.EffectiveProtocol = config.ProtocolQUIC
			return rep, nil
		}
		if mode == ModeQUIC {
			if err != nil {
				return rep, err
			}
			return rep, errors.New("quic probe did not produce enough healthy candidates")
		}
	}
	rep, err := runMode(ctx, cfg, ModeHTTP2)
	rep.Mode = string(mode)
	rep.EffectiveProtocol = config.ProtocolHTTP2
	return rep, err
}
