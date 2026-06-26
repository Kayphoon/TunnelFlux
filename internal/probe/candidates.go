package probe

import (
	"net/netip"
	"os"
	"strings"

	"github.com/kayphoon/tunnelflux/internal/config"
)

func candidates(cfg config.Config) ([]string, error) {
	var raw []string
	if cfg.Edge.CandidateFile != "" {
		if data, err := os.ReadFile(cfg.Edge.CandidateFile); err == nil {
			raw = append(raw, strings.Fields(string(data))...)
		}
	}
	raw = append(raw, cfg.Edge.Candidates...)
	seen := map[string]bool{}
	var out []string
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" || strings.HasPrefix(item, "#") {
			continue
		}
		var expanded []string
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				continue
			}
			expanded = expandPrefix(p, cfg.Edge.MaxCandidates)
		} else if addr, err := netip.ParseAddr(item); err == nil {
			expanded = []string{addr.String()}
		}
		for _, ip := range expanded {
			if !seen[ip] {
				seen[ip] = true
				out = append(out, ip)
				if cfg.Edge.MaxCandidates > 0 && len(out) >= cfg.Edge.MaxCandidates {
					return out, nil
				}
			}
		}
	}
	return out, nil
}

func expandPrefix(p netip.Prefix, max int) []string {
	p = p.Masked()
	var out []string
	addr := p.Addr()
	for p.Contains(addr) {
		if addr.Is4() {
			last := addr.As4()[3]
			if last != 0 && last != 255 {
				out = append(out, addr.String())
			}
		} else {
			out = append(out, addr.String())
		}
		if max > 0 && len(out) >= max {
			return out
		}
		next := addr.Next()
		if !next.IsValid() || next.Compare(addr) <= 0 {
			break
		}
		addr = next
	}
	return out
}
