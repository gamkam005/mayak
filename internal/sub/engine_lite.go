//go:build lite

package sub

import (
	"context"
	"errors"
	"net"
)

// Available — в облегчённой сборке (для роутеров) ядра Xray нет:
// подписки разбираются, но подключаться через них нельзя.
const Available = false

// ErrNoEngine — сборка без Xray.
var ErrNoEngine = errors.New("эта сборка без ядра Xray (lite): подписки недоступны")

type Engine struct{}

func NewEngine(map[string]any) (*Engine, error) { return nil, ErrNoEngine }

func (e *Engine) Dial(context.Context, string) (net.Conn, error) { return nil, ErrNoEngine }

func (e *Engine) Close() error { return nil }
