package probe

import (
	"math"
	"sort"
)

func summarize(vals []float64) Result {
	if len(vals) == 0 {
		return Result{MedianMS: 999999, MeanMS: 999999, MinMS: 999999, MaxMS: 999999, StdevMS: 999999}
	}
	cp := append([]float64(nil), vals...)
	sort.Float64s(cp)
	var sum float64
	for _, v := range cp {
		sum += v
	}
	mean := sum / float64(len(cp))
	variance := 0.0
	for _, v := range cp {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(cp))
	median := cp[len(cp)/2]
	if len(cp)%2 == 0 {
		median = (cp[len(cp)/2-1] + cp[len(cp)/2]) / 2
	}
	return Result{
		MedianMS: median,
		MeanMS:   mean,
		MinMS:    cp[0],
		MaxMS:    cp[len(cp)-1],
		StdevMS:  math.Sqrt(variance),
	}
}

func score(r Result) float64 {
	if r.OK == 0 {
		return 999999999
	}
	return r.MedianMS + r.StdevMS*0.35 + r.MaxMS*0.05 + float64(r.Fail)*1000
}

func better(a, b Result) bool {
	if a.OK != b.OK {
		return a.OK > b.OK
	}
	if a.Fail != b.Fail {
		return a.Fail < b.Fail
	}
	if a.Score != b.Score {
		return a.Score < b.Score
	}
	return a.IP < b.IP
}

func uniqueTop(rows []Result, n int) []Result {
	var top []Result
	seen := map[string]bool{}
	for _, r := range rows {
		if r.OK == 0 || seen[r.IP] {
			continue
		}
		seen[r.IP] = true
		top = append(top, r)
		if len(top) >= n {
			break
		}
	}
	return top
}

func minTop(topN, hostnames int) int {
	if hostnames <= 0 {
		hostnames = 2
	}
	if topN <= 0 || topN > hostnames {
		topN = hostnames
	}
	if topN > 2 {
		return 2
	}
	return topN
}
