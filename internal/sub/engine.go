//go:build !lite

package sub

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	// протоколы и транспорты, которые встречаются в подписках
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/hysteria"
	_ "github.com/xtls/xray-core/proxy/shadowsocks"
	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

type nullLog struct{}

func (nullLog) Handle(xlog.Message) {}

// Xray пишет предупреждения об устаревших транспортах прямо в stderr —
// для бесплатных серверов это шум.
func init() { xlog.RegisterHandler(nullLog{}) }

// Available — в сборке есть ядро Xray (в -tags lite его нет).
const Available = true

// Engine — запущенный экземпляр Xray с одним исходящим.
type Engine struct {
	inst *core.Instance
}

// NewEngine запускает Xray для outbound ob.
func NewEngine(ob map[string]any) (*Engine, error) {
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "none"},
		"outbounds": []any{ob},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var c conf.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("конфиг: %w", err)
	}
	pb, err := c.Build()
	if err != nil {
		return nil, fmt.Errorf("конфиг: %w", err)
	}
	inst, err := core.New(pb)
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, err
	}
	return &Engine{inst: inst}, nil
}

// Dial открывает TCP до target (host:port) через сервер.
func (e *Engine) Dial(ctx context.Context, target string) (net.Conn, error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	// Xray привязывает поток к ctx: отмена рвёт уже открытое соединение,
	// поэтому живём до Close(), а ctx отменяет только ожидание.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return core.Dial(context.WithoutCancel(ctx), e.inst, xnet.TCPDestination(xnet.ParseAddress(h), xnet.Port(port)))
}

func (e *Engine) Close() error { return e.inst.Close() }
