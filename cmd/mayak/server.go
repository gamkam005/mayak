package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mayak/internal/protocol"
	"mayak/internal/server"
)

func runKeygen() int {
	fmt.Println(protocol.NewSecret())
	return 0
}

func runServer(args []string) int {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":443", "адрес:порт для HTTPS")
	state := fs.String("state", "/etc/mayak", "каталог для секрета и сертификата")
	secret := fs.String("secret", "", "секрет (по умолчанию берётся/создаётся в <state>/secret)")
	certF := fs.String("cert", "", "свой сертификат (PEM), например от Let's Encrypt")
	keyF := fs.String("key", "", "ключ к сертификату (PEM)")
	cn := fs.String("cn", "static.example.net", "имя в самоподписанном сертификате")
	public := fs.String("public", "", "внешний IP/домен сервера — для ссылки")
	sni := fs.String("sni", "", "SNI, который положить в ссылку (по умолчанию = cn или домен)")
	site := fs.String("site", "Statika CDN", "название сайта-заглушки")
	verbose := fs.Bool("v", false, "подробный журнал")
	_ = fs.Parse(args)

	logger := log.New(os.Stderr, "mayak ", log.LstdFlags)
	if err := os.MkdirAll(*state, 0o700); err != nil {
		logger.Printf("state dir: %v", err)
		return 1
	}
	if *secret == "" {
		p := filepath.Join(*state, "secret")
		if b, err := os.ReadFile(p); err == nil {
			*secret = strings.TrimSpace(string(b))
		} else {
			*secret = protocol.NewSecret()
			if err := os.WriteFile(p, []byte(*secret+"\n"), 0o600); err != nil {
				logger.Printf("save secret: %v", err)
				return 1
			}
			logger.Printf("создан новый секрет: %s", p)
		}
	}
	var cert tls.Certificate
	var err error
	selfSigned := false
	if *certF != "" {
		cert, err = tls.LoadX509KeyPair(*certF, *keyF)
	} else {
		cert, err = loadOrMakeCert(*state, *cn)
		selfSigned = true
	}
	if err != nil {
		logger.Printf("certificate: %v", err)
		return 1
	}
	pinSum := sha256.Sum256(cert.Certificate[0])
	pin := hex.EncodeToString(pinSum[:])

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Printf("listen: %v", err)
		return 1
	}
	tcfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	cfg := server.Config{SiteName: *site}
	if *verbose {
		cfg.Log = logger
	}
	srv := server.New(*secret, cfg)

	host := *public
	if host == "" {
		host = guessIP()
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	link := protocol.Link{Secret: *secret, Server: net.JoinHostPort(host, port), FP: "chrome", Mode: "auto", Name: "МАЯК"}
	switch {
	case *sni != "":
		link.SNI = *sni
	case selfSigned:
		link.SNI = *cn
	}
	if selfSigned {
		link.Pin = pin
	}
	_ = os.WriteFile(filepath.Join(*state, "link.txt"), []byte(link.String()+"\n"), 0o600)
	logger.Printf("МАЯК %s слушает %s (сертификат: %s, pin %s…)", version, ln.Addr(), map[bool]string{true: "самоподписанный", false: *certF}[selfSigned], pin[:16])
	fmt.Println("\nСсылка для клиента (сохранена в " + filepath.Join(*state, "link.txt") + "):\n\n  " + link.String() + "\n")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx, tls.NewListener(ln, tcfg)); err != nil && ctx.Err() == nil {
		logger.Printf("serve: %v", err)
		return 1
	}
	return 0
}

func loadOrMakeCert(dir, cn string) (tls.Certificate, error) {
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return tls.LoadX509KeyPair(cp, kp)
}

func guessIP() string {
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}
