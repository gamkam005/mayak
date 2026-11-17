package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// Link — содержимое ссылки mayak://секрет@хост:порт?sni=..&pin=..&fp=..&mode=..&budget=..#имя
type Link struct {
	Secret, Server, SNI, Pin, FP, Mode, Name string
	Budget                                 int
}

func ParseLink(s string) (Link, error) {
	var l Link
	u, err := url.Parse(s)
	if err != nil {
		return l, err
	}
	if u.Scheme != "mayak" {
		return l, errors.New("ссылка должна начинаться с mayak://")
	}
	if u.User == nil || u.User.Username() == "" {
		return l, errors.New("в ссылке нет секрета")
	}
	l.Secret = u.User.Username()
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return l, fmt.Errorf("адрес сервера: %w", err)
	}
	l.Server = u.Host
	q := u.Query()
	l.SNI, l.Pin, l.FP, l.Mode = q.Get("sni"), q.Get("pin"), q.Get("fp"), q.Get("mode")
	l.Budget, _ = strconv.Atoi(q.Get("budget"))
	l.Name = u.Fragment
	return l, nil
}

func (l Link) String() string {
	q := url.Values{}
	if l.SNI != "" {
		q.Set("sni", l.SNI)
	}
	if l.Pin != "" {
		q.Set("pin", l.Pin)
	}
	if l.FP != "" {
		q.Set("fp", l.FP)
	}
	if l.Mode != "" {
		q.Set("mode", l.Mode)
	}
	if l.Budget > 0 {
		q.Set("budget", strconv.Itoa(l.Budget))
	}
	u := url.URL{Scheme: "mayak", User: url.User(l.Secret), Host: l.Server, RawQuery: q.Encode(), Fragment: l.Name}
	return u.String()
}

// NewSecret — случайный секрет (24 байта, base64url).
func NewSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
