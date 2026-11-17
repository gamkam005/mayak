package sub

import (
	"context"
	"os"
	"testing"
	"time"
)

// MAYAK_LIVE=1 go test ./internal/sub -run TestLive -v — проверка реальных подписок с этой машины.
func TestLive(t *testing.T) {
	if os.Getenv("MAYAK_LIVE") == "" {
		t.Skip("MAYAK_LIVE=1")
	}
	for _, src := range Presets {
		p := New(Options{Sources: []Source{src}, MaxCandidates: 120, ProbeMax: 120, ProbeWorkers: 16, StateDir: t.TempDir()})
		t0 := time.Now()
		_ = p.Check(context.Background(), true)
		s := p.Snapshot()
		ss := s.Sources[0]
		tcpOK, probed, open := 0, 0, 0
		p.mu.Lock()
		for _, r := range p.res {
			probed++
			if r.Err != "TCP: нет ответа" {
				tcpOK++
			}
			if r.OK && !r.Limited {
				open++
			}
		}
		p.mu.Unlock()
		best := ""
		for i, n := range s.Nodes {
			if i < 3 {
				best += " " + n.Proto + "/" + n.Net + "/" + n.Sec + "=" + itoa(n.Delay) + "ms"
			}
		}
		t.Logf("%-22s parsed %4d (bad %d, uniq %d) mix %v | checked %d, TCP ok %d, alive %d (open blocked: %d) | %s |%s",
			src.ID, ss.Count, ss.Bad, s.Total, ss.Mix, probed, tcpOK, s.Alive, open, time.Since(t0).Round(time.Second), best)
		p.closeAll()
	}
}
