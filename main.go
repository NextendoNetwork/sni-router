// sni-router: a minimal TLS SNI passthrough proxy. It peeks the ClientHello on
// :443, reads the SNI hostname, and forwards the raw TLS stream to the right
// backend (MK8 auth vs SSBU auth) WITHOUT terminating TLS — so both games' NEX
// auth servers can share :443. The backends terminate TLS themselves (WSS).
//
//	g2b309e01-...srv.nintendo.net  -> MK8 auth   (BACKEND_MK8)
//	g23380901-...srv.nintendo.net  -> SSBU auth  (BACKEND_SSBU)
//	g25c08801-...srv.nintendo.net  -> ARMS auth  (BACKEND_ARMS)
//	g2ee2e300-...srv.nintendo.net  -> ACNH auth  (BACKEND_ACNH)
//	g21f12900-...srv.nintendo.net  -> SMB35 auth (BACKEND_SMB35)
//	g23932a00-...srv.nintendo.net  -> Mario Tennis Aces auth (BACKEND_TENNIS)
//	g22306d00-...srv.nintendo.net  -> Super Mario Maker 2 auth (BACKEND_SMM2)
//	g28abaa00-...srv.nintendo.net  -> Mario Party Superstars auth (BACKEND_MPS)
//	g255ba201-...srv.nintendo.net  -> Super Mario Odyssey auth (BACKEND_SMO)
//	g26cfaf00-...srv.nintendo.net  -> Mario Strikers: Battle League auth (BACKEND_STRIKERS)
//	g2896bd04-...srv.nintendo.net  -> Monster Hunter Generations Ultimate auth (BACKEND_MHGU)
//	g211a3f00-...srv.nintendo.net  -> Mario Golf: Super Rush auth (BACKEND_GOLF) -- captured
//	                                   live from a real ranked-match attempt (2026-08-28); not
//	                                   yet cross-checked against a static binary read, so this
//	                                   could be the Game Server ID rather than the access key
//	                                   the way MPS's initial g28abaa00 guess was -- see
//	                                   mario-golf-super-rush's README.
//	*.acbaa.srv.nintendo.net       -> ACNH REST companion API (BACKEND_ACNH_API)
//	*.ndas.srv.nintendo.net        -> nx-dauth   (BACKEND_DAUTH)
//	*.dragons.nintendo.net         -> nx-dauth   (BACKEND_DAUTH)
//	anything else                  -> BACKEND_DEFAULT (MK8 by default)
package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	listen := envOr("SNI_LISTEN", ":443")
	mk8 := envOr("BACKEND_MK8", "127.0.0.1:8443")
	ssbu := envOr("BACKEND_SSBU", "127.0.0.1:8444")
	arms := envOr("BACKEND_ARMS", "127.0.0.1:8445")
	acnh := envOr("BACKEND_ACNH", "127.0.0.1:8447")
	acnhAPI := envOr("BACKEND_ACNH_API", "127.0.0.1:8448")
	smb35 := envOr("BACKEND_SMB35", "127.0.0.1:8449")
	tennis := envOr("BACKEND_TENNIS", "127.0.0.1:8450")
	smm2 := envOr("BACKEND_SMM2", "127.0.0.1:8451")
	mps := envOr("BACKEND_MPS", "127.0.0.1:8452")
	smo := envOr("BACKEND_SMO", "127.0.0.1:8453")
	strikers := envOr("BACKEND_STRIKERS", "127.0.0.1:8454")
	mhgu := envOr("BACKEND_MHGU", "127.0.0.1:8456")
	golf := envOr("BACKEND_GOLF", "127.0.0.1:8457")
	dauth := envOr("BACKEND_DAUTH", "127.0.0.1:8446")
	def := envOr("BACKEND_DEFAULT", mk8)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("SNI router on %s -> mk8=%s ssbu=%s arms=%s acnh=%s acnhAPI=%s smb35=%s tennis=%s smm2=%s mps=%s smo=%s strikers=%s mhgu=%s golf=%s dauth=%s default=%s", listen, mk8, ssbu, arms, acnh, acnhAPI, smb35, tennis, smm2, mps, smo, strikers, mhgu, golf, dauth, def)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, mk8, ssbu, arms, acnh, acnhAPI, smb35, tennis, smm2, mps, smo, strikers, mhgu, golf, dauth, def)
	}
}

func handle(c net.Conn, mk8, ssbu, arms, acnh, acnhAPI, smb35, tennis, smm2, mps, smo, strikers, mhgu, golf, dauth, def string) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, sni, err := peekClientHello(c)
	_ = c.SetReadDeadline(time.Time{})

	backend := def
	if err == nil {
		switch {
		case strings.Contains(sni, "g2b309e01"):
			backend = mk8
		case strings.Contains(sni, "g23380901"):
			backend = ssbu
		case strings.Contains(sni, "g25c08801"):
			backend = arms
		case strings.Contains(sni, "g2ee2e300"):
			backend = acnh
		case strings.Contains(sni, "g21f12900"):
			backend = smb35
		case strings.Contains(sni, "g23932a00"):
			backend = tennis
		case strings.Contains(sni, "g22306d00"):
			backend = smm2
		case strings.Contains(sni, "g28abaa00"):
			backend = mps
		case strings.Contains(sni, "g255ba201"):
			backend = smo
		case strings.Contains(sni, "g26cfaf00"):
			backend = strikers
		case strings.Contains(sni, "g2896bd04"):
			backend = mhgu
		case strings.Contains(sni, "g211a3f00"):
			backend = golf
		case strings.Contains(sni, "acbaa.srv.nintendo.net"):
			backend = acnhAPI
		case strings.Contains(sni, "ndas.srv.nintendo.net"), strings.Contains(sni, "dragons.nintendo.net"):
			backend = dauth
		}
	}
	log.Printf("conn from %s sni=%q -> %s", c.RemoteAddr(), sni, backend)

	up, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("dial %s: %v", backend, err)
		return
	}
	defer up.Close()

	if _, err := up.Write(hello); err != nil { // replay the buffered ClientHello
		return
	}
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

// peekClientHello reads the first TLS record (the ClientHello), returns the raw
// bytes (to replay to the backend) and the parsed SNI host.
func peekClientHello(c net.Conn) ([]byte, string, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return hdr, "", err
	}
	if hdr[0] != 0x16 { // not a TLS handshake record
		return hdr, "", errors.New("not a TLS handshake")
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, recLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return append(hdr, body...), "", err
	}
	full := append(append([]byte{}, hdr...), body...)
	return full, parseSNI(body), nil
}

// parseSNI extracts the server_name from a TLS ClientHello handshake message.
func parseSNI(b []byte) string {
	// b[0]=HandshakeType(1=ClientHello), b[1:4]=len, b[4:6]=version, b[6:38]=random
	if len(b) < 38 || b[0] != 0x01 {
		return ""
	}
	p := 38
	if p >= len(b) {
		return ""
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + csLen
	if p+1 > len(b) {
		return ""
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	end := p + extLen
	for p+4 <= end && p+4 <= len(b) {
		etype := binary.BigEndian.Uint16(b[p:])
		elen := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if etype == 0x0000 { // server_name
			if p+5 <= len(b) {
				nameLen := int(binary.BigEndian.Uint16(b[p+3:]))
				if p+5+nameLen <= len(b) {
					return string(b[p+5 : p+5+nameLen])
				}
			}
		}
		p += elen
	}
	return ""
}
