package client

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

type sample struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`   // байт/с
	Down int64 `json:"down"` // байт/с
	Str  int   `json:"streams"`
}

type stats struct {
	upBytes, downBytes atomic.Int64
	legs, dials        atomic.Int64
	errors, retries    atomic.Int64
	dups, resets       atomic.Int64
	streamsTotal       atomic.Int64

	mu       sync.Mutex
	lastErr  string
	lastErrT time.Time
	samples  []sample
	connN    int64
	connMax  int64 // максимум байт, принятых одним TLS-соединением
	connSum  int64
	connLegs int64
	recent   []int64 // байты последних закрытых соединений
	rttSum   time.Duration
	rttN     int64
}

func (s *stats) setLastErr(e string) {
	s.mu.Lock()
	s.lastErr, s.lastErrT = e, time.Now()
	s.mu.Unlock()
}

func (s *stats) noteConn(rd, wr int64, legs int) {
	s.mu.Lock()
	s.connN++
	s.connSum += rd
	s.connLegs += int64(legs)
	if rd > s.connMax {
		s.connMax = rd
	}
	s.recent = append(s.recent, rd)
	if len(s.recent) > 96 {
		s.recent = s.recent[len(s.recent)-96:]
	}
	s.mu.Unlock()
}

func (s *stats) legRTT(d time.Duration) {
	s.mu.Lock()
	s.rttSum += d
	s.rttN++
	s.mu.Unlock()
}

func (s *stats) recentDown() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum int64
	for i := len(s.samples) - 1; i >= 0 && i >= len(s.samples)-3; i-- {
		sum += s.samples[i].Down
	}
	return sum
}

func (c *Client) sampler(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lu, ld int64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			u, d := c.st.upBytes.Load(), c.st.downBytes.Load()
			c.mu.Lock()
			n := len(c.streams)
			c.mu.Unlock()
			c.st.mu.Lock()
			c.st.samples = append(c.st.samples, sample{T: now.Unix(), Up: u - lu, Down: d - ld, Str: n})
			if len(c.st.samples) > 180 {
				c.st.samples = c.st.samples[len(c.st.samples)-180:]
			}
			c.st.mu.Unlock()
			lu, ld = u, d
		}
	}
}

// Snapshot — всё для панели.
type Snapshot struct {
	Server       string   `json:"server"`
	SNI          string   `json:"sni"`
	Fingerprint  string   `json:"fingerprint"`
	Mode         string   `json:"mode"`
	Profile      Profile  `json:"profile"`
	Session      string   `json:"session"`
	Streams      int      `json:"streams"`
	StreamsTotal int64    `json:"streams_total"`
	UpBytes      int64    `json:"up_bytes"`
	DownBytes    int64    `json:"down_bytes"`
	Legs         int64    `json:"legs"`
	Dials        int64    `json:"dials"`
	Errors       int64    `json:"errors"`
	Retries      int64    `json:"retries"`
	Dups         int64    `json:"dups"`
	Resets       int64    `json:"resets"`
	ConnClosed   int64    `json:"conn_closed"`
	ConnMax      int64    `json:"conn_max_bytes"`
	ConnAvg      int64    `json:"conn_avg_bytes"`
	LegsPerConn  float64  `json:"legs_per_conn"`
	AvgLegMs     int64    `json:"avg_leg_ms"`
	LastErr      string   `json:"last_err"`
	LastErrAgo   int64    `json:"last_err_ago_s"`
	Samples      []sample `json:"samples"`
	Events       []Event  `json:"events"`
	Targets      []string `json:"targets"`
	RecentConns  []int64  `json:"recent_conns"`
	Uptime       int64    `json:"uptime_s"`
}

var startTime = time.Now()

func (c *Client) Snapshot() Snapshot {
	c.mu.Lock()
	n := len(c.streams)
	sid := c.sid.String()[:8]
	var targets []string
	for _, st := range c.streams {
		if len(targets) < 12 {
			targets = append(targets, st.target)
		}
	}
	c.mu.Unlock()
	s := &c.st
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{
		Server: c.opt.Server, SNI: c.opt.SNI, Fingerprint: c.opt.Fingerprint, Mode: c.opt.Mode,
		Profile: c.Profile(), Session: sid, Streams: n, StreamsTotal: s.streamsTotal.Load(),
		UpBytes: s.upBytes.Load(), DownBytes: s.downBytes.Load(), Legs: s.legs.Load(), Dials: s.dials.Load(),
		Errors: s.errors.Load(), Retries: s.retries.Load(), Dups: s.dups.Load(), Resets: s.resets.Load(),
		ConnClosed: s.connN, ConnMax: s.connMax, LastErr: s.lastErr, Targets: targets,
		Samples: append([]sample(nil), s.samples...), Events: c.events.list(),
		RecentConns: append([]int64(nil), s.recent...),
		Uptime: int64(time.Since(startTime).Seconds()),
	}
	if s.connN > 0 {
		snap.ConnAvg = s.connSum / s.connN
		snap.LegsPerConn = float64(s.connLegs) / float64(s.connN)
	}
	if s.rttN > 0 {
		snap.AvgLegMs = (s.rttSum / time.Duration(s.rttN)).Milliseconds()
	}
	if !s.lastErrT.IsZero() {
		snap.LastErrAgo = int64(time.Since(s.lastErrT).Seconds())
	}
	return snap
}

// Event — запись журнала событий.
type Event struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

type eventLog struct {
	mu  sync.Mutex
	max int
	ev  []Event
}

func newEventLog(max int) *eventLog { return &eventLog{max: max} }

func (l *eventLog) add(kind, text string) {
	l.mu.Lock()
	l.ev = append(l.ev, Event{T: time.Now().Unix(), Kind: kind, Text: text})
	if len(l.ev) > l.max {
		l.ev = l.ev[len(l.ev)-l.max:]
	}
	l.mu.Unlock()
}

func (l *eventLog) list() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.ev))
	for i := range l.ev {
		out[i] = l.ev[len(l.ev)-1-i]
	}
	return out
}
