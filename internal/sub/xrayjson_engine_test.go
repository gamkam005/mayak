//go:build !lite

package sub

import "testing"

func TestXrayJSONEngine(t *testing.T) {
	ns, _ := ParseText(xrayJSONSub)
	for i, n := range ns {
		e, err := NewEngine(withIP(n.ob, n.Host, "127.0.0.1"))
		if err != nil {
			t.Errorf("node %d: engine: %v", i, err)
			continue
		}
		_ = e.Close()
	}
}
