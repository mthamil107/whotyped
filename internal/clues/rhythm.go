package clues

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/whotyped/whotyped/internal/rules"
	"github.com/whotyped/whotyped/internal/session"
)

const (
	WeightRhythmBurst     = 20
	WeightRhythmRegular   = 10
	WeightRhythmSubsecond = 10
	WeightRhythmSustained = 10

	burstCount          = 6
	burstSpan           = 5 * time.Minute
	regularMinSamples   = 6
	regularMaxCV        = 0.35
	subsecondMinSamples = 4
	subsecondMedian     = 1500 * time.Millisecond
	subsecondMaxGap     = 60 * time.Second
	sustainedCount      = 25

	// dedupeGap merges an sshlog exec channel with the auditd execve records
	// it spawns (bash, then the tool) so one command is counted once.
	dedupeGap = 200 * time.Millisecond
)

// Rhythm measures how commands arrive in time. Tools fire many short exec
// channels at machine-regular intervals; humans do not.
type Rhythm struct{}

// ID implements Detector.
func (Rhythm) ID() string { return "rhythm" }

// Evaluate implements Detector.
func (Rhythm) Evaluate(t *session.Track, _ *rules.Pack, now time.Time) []Clue {
	if t == nil {
		return nil
	}
	times, noun := execTimes(t)
	n := len(times)
	if n < subsecondMinSamples {
		return nil
	}
	gaps := make([]time.Duration, 0, n-1)
	for i := 1; i < n; i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]))
	}
	med := medianGap(gaps, subsecondMaxGap)
	cv := coefficientOfVariation(gaps)
	span := times[n-1].Sub(times[0])
	summary := fmt.Sprintf("%d %s in %s, median gap %s, cv %.2f", n, noun, roundDur(span), roundDur(med), cv)

	var out []Clue
	if peak := maxInSpan(times, burstSpan); peak >= burstCount {
		out = append(out, Clue{ID: "rhythm.burst", Category: CatRhythm, Weight: WeightRhythmBurst, Evidence: summary, TS: now})
	}
	if n >= regularMinSamples && cv < regularMaxCV {
		out = append(out, Clue{ID: "rhythm.regular", Category: CatRhythm, Weight: WeightRhythmRegular,
			Evidence: fmt.Sprintf("gaps cv %.2f over %d %s", cv, n, noun), TS: now})
	}
	if med > 0 && med < subsecondMedian {
		out = append(out, Clue{ID: "rhythm.subsecond", Category: CatRhythm, Weight: WeightRhythmSubsecond,
			Evidence: fmt.Sprintf("median gap %s over %d %s", roundDur(med), n, noun), TS: now})
	}
	if n >= sustainedCount {
		out = append(out, Clue{ID: "rhythm.sustained", Category: CatRhythm, Weight: WeightRhythmSustained,
			Evidence: fmt.Sprintf("%d %s in %s", n, noun, roundDur(span)), TS: now})
	}
	return out
}

// execTimes returns the de-duplicated, sorted command timestamps and the noun
// to use in evidence ("exec channels" when every sample is an SSH exec channel).
func execTimes(t *session.Track) ([]time.Time, string) {
	if len(t.Execs) == 0 {
		return nil, "commands"
	}
	all := make([]time.Time, 0, len(t.Execs))
	noun := "exec channels"
	for _, e := range t.Execs {
		all = append(all, e.TS)
		if e.Origin != "sshlog" {
			noun = "commands"
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Before(all[j]) })
	out := all[:1]
	for _, ts := range all[1:] {
		if ts.Sub(out[len(out)-1]) >= dedupeGap {
			out = append(out, ts)
		}
	}
	return out, noun
}

// maxInSpan is the largest number of timestamps falling in any window of span.
func maxInSpan(times []time.Time, span time.Duration) int {
	best, lo := 0, 0
	for hi := range times {
		for times[hi].Sub(times[lo]) > span {
			lo++
		}
		if n := hi - lo + 1; n > best {
			best = n
		}
	}
	return best
}

// medianGap is the median of gaps no longer than maxGap (idle pauses between
// bursts should not hide a sub-second cadence), or 0 if none qualify.
func medianGap(gaps []time.Duration, maxGap time.Duration) time.Duration {
	var short []time.Duration
	for _, g := range gaps {
		if g <= maxGap {
			short = append(short, g)
		}
	}
	if len(short) == 0 {
		return 0
	}
	sort.Slice(short, func(i, j int) bool { return short[i] < short[j] })
	m := len(short) / 2
	if len(short)%2 == 1 {
		return short[m]
	}
	return (short[m-1] + short[m]) / 2
}

// coefficientOfVariation is stddev/mean of the gaps (population stddev).
func coefficientOfVariation(gaps []time.Duration) float64 {
	if len(gaps) < 2 {
		return math.Inf(1)
	}
	var sum float64
	for _, g := range gaps {
		sum += float64(g)
	}
	mean := sum / float64(len(gaps))
	if mean <= 0 {
		return math.Inf(1)
	}
	var ss float64
	for _, g := range gaps {
		d := float64(g) - mean
		ss += d * d
	}
	return math.Sqrt(ss/float64(len(gaps))) / mean
}

// roundDur renders a duration compactly: 640ms, 4.2s, 1m32s.
func roundDur(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}
