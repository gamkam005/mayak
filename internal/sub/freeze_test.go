package sub

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		d    DL
		want string
	}{
		{DL{Target: FreezeSmall, Bytes: FreezeSmall, Mbps: 5}, StatusWorking},
		{DL{Target: FreezeSmall, Bytes: FreezeSmall, Mbps: 0.05}, StatusSlow},
		{DL{Target: FreezeSmall, Bytes: 16000, Stalled: true}, StatusFrozen},
		{DL{Target: FreezeSmall, Bytes: 0, Stalled: true}, StatusFrozen},
		{DL{Target: FreezeSmall, Bytes: 100 << 10, Stalled: true}, StatusSlow},
		{DL{Target: FreezeSmall, Bytes: 0, Err: "HTTP 403"}, StatusReachable},
	}
	for i, c := range cases {
		if g := classify(c.d); g != c.want {
			t.Errorf("%d: %s, want %s", i, g, c.want)
		}
	}
}

// Правило «сбой → 2 проверки вне очереди» для загрузки: работавший сервер
// понижается, только если и повторные загрузки встали; один удачный повтор
// спасает его.
func TestFreezeRetriesAndRanking(t *testing.T) {
	p := New(Options{})
	p.nodes = map[string]*Node{"a": {ID: "a", Name: "a"}, "b": {ID: "b", Name: "b"}}
	p.order = []string{"a", "b"}
	p.probeFn = func(ctx context.Context, n *Node, u string, to time.Duration) (time.Duration, error) {
		if n.ID == "a" {
			return 10 * time.Millisecond, nil // a быстрее по задержке
		}
		return 80 * time.Millisecond, nil
	}
	calls := map[string]int{}
	p.dlFn = func(ctx context.Context, n *Node, target int64) DL {
		calls[n.ID]++
		if n.ID == "a" {
			return DL{Target: target, Bytes: 16384, Stalled: true, Class: StatusFrozen}
		}
		if calls["b"] == 1 { // первая попытка встала, вторая прошла
			return DL{Target: target, Bytes: 9000, Stalled: true, Class: StatusFrozen}
		}
		return DL{Target: target, Bytes: target, Mbps: 20, Class: StatusWorking}
	}
	for _, id := range []string{"a", "b"} {
		r := &Result{ID: id, Checked: time.Now()}
		p.probeNode(context.Background(), p.nodes[id], r, 2, true)
		p.res[id] = r
	}
	p.rankLocked()
	if p.res["a"].Status != StatusFrozen || p.res["b"].Status != StatusWorking {
		t.Fatalf("a=%s b=%s", p.res["a"].Status, p.res["b"].Status)
	}
	if calls["a"] != 3 || calls["b"] != 2 {
		t.Errorf("попыток: a=%d (нужно 1+2), b=%d (нужно 2)", calls["a"], calls["b"])
	}
	if p.alive[0] != "b" {
		t.Errorf("первым должен идти рабочий b, а не замороженный a: %v", p.alive)
	}
	// активный замороженный — автовыбор уходит на рабочий
	p.active = "a"
	p.rankLocked()
	if p.active != "" {
		t.Errorf("active остался на замороженном")
	}
	_ = errors.New
}
