package client

import (
	"crypto/rand"
	"encoding/hex"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Расширение Trust Anchor IDs (0xca34), которое шлёт Chrome 156; данные
// статичны для сборки браузера — сняты с настоящего Chrome 156.0.8078.47.
var chromeTrustAnchors, _ = hex.DecodeString("00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f")

func greaseValue() uint16 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	v := uint16(b[0]&0xf0) | 0x0a
	return v<<8 | v
}

// chrome156Spec — пресет uTLS «Chrome» с доработками до Chrome 156:
// post-quantum подписи ML-DSA (0x0904–0x0906) с GREASE в начале списка и
// расширение Trust Anchor IDs. Порядок расширений перемешивается, как в Chrome.
func chrome156Spec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, err
	}
	for _, e := range spec.Extensions {
		if sa, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			pre := []utls.SignatureScheme{utls.SignatureScheme(greaseValue()), 0x0904, 0x0905, 0x0906}
			sa.SupportedSignatureAlgorithms = append(pre, sa.SupportedSignatureAlgorithms...)
		}
	}
	// вставляем перед завершающим GREASE и перемешиваем заново
	n := len(spec.Extensions)
	ext := &utls.GenericExtension{Id: 0xca34, Data: chromeTrustAnchors}
	spec.Extensions = append(spec.Extensions[:n-1], ext, spec.Extensions[n-1])
	spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	return &spec, nil
}

// newUClient создаёт TLS-клиент с нужным отпечатком.
func newUClient(c net.Conn, cfg *utls.Config, fp string) *utls.UConn {
	if fp == "" || fp == "chrome" || fp == "chrome156" {
		if spec, err := chrome156Spec(); err == nil {
			uc := utls.UClient(c, cfg, utls.HelloCustom)
			if err := uc.ApplyPreset(spec); err == nil {
				return uc
			}
		}
	}
	if fp == "chrome-utls" {
		return utls.UClient(c, cfg, utls.HelloChrome_Auto)
	}
	return utls.UClient(c, cfg, helloID(fp))
}
