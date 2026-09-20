// sni-router: a minimal TLS SNI passthrough proxy. It peeks the ClientHello on
// :443, reads the SNI hostname, and forwards the raw TLS stream to the right
// backend (MK8 auth vs SSBU auth) WITHOUT terminating TLS — so both games' NEX
// auth servers can share :443. The backends terminate TLS themselves (WSS).
//
//	g2b309e01-...srv.nintendo.net  -> MK8 auth   (BACKEND_MK8)
//	g23380901-...srv.nintendo.net  -> SSBU auth  (BACKEND_SSBU)
//	g25c08801-...srv.nintendo.net  -> ARMS auth  (BACKEND_ARMS)
//	g2ee2e300-...srv.nintendo.net  -> ACNH auth  (BACKEND_ACNH)
//	*.ndas.srv.nintendo.net        -> nx-dauth   (BACKEND_DAUTH)
//	*.dragons.nintendo.net         -> nx-dauth   (BACKEND_DAUTH)
//	*.demonware.net                -> Diablo III auth, diablo-3 (BACKEND_D3)
//	anything else                  -> BACKEND_DEFAULT (MK8 by default)
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	dauth := envOr("BACKEND_DAUTH", "127.0.0.1:8446")
	// Diablo III parle Demonware, pas NEX : son auth HTTPS
	// (crimson-switch-auth3.*.demonware.net) va au serveur diablo-3. Le lobby
	// (TCP/UDP 3074) ne passe pas par ici.
	d3 := envOr("BACKEND_D3", "127.0.0.1:8460")
	def := envOr("BACKEND_DEFAULT", mk8)
	proxyProto := envOr("SNI_PROXY_PROTOCOL", "") == "1"

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err)
	}
	log.Printf("SNI router on %s -> mk8=%s ssbu=%s arms=%s acnh=%s dauth=%s d3=%s default=%s", listen, mk8, ssbu, arms, acnh, dauth, d3, def)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, mk8, ssbu, arms, acnh, dauth, d3, def, proxyProto)
	}
}

func handle(c net.Conn, mk8, ssbu, arms, acnh, dauth, d3, def string, proxyProto bool) {
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, sni, err := peekClientHello(c)
	_ = c.SetReadDeadline(time.Time{})

	backend := def
	// Les serveurs d'auth NEX corrèlent l'auth et la connexion secure par IP
	// source. Nous étant un relais, ils voient la nôtre (127.0.0.1) alors que la
	// secure arrive en direct depuis la console : « ticketless CONNECT with no
	// recent auth from this address ». On préfixe donc l'en-tête PROXY pour leur
	// donner la vraie adresse (ils écoutent en ListenSecureProxy). Réservé aux
	// backends NEX : nx-dauth et l'upstream ne comprennent pas cet en-tête.
	wantProxy := false
	if err == nil {
		switch {
		case strings.Contains(sni, "g2b309e01"):
			backend, wantProxy = mk8, proxyProto
		case strings.Contains(sni, "g23380901"):
			backend, wantProxy = ssbu, proxyProto
		case strings.Contains(sni, "g25c08801"):
			backend, wantProxy = arms, proxyProto
		case strings.Contains(sni, "g2ee2e300"):
			backend, wantProxy = acnh, proxyProto
		case strings.Contains(sni, "ndas.srv.nintendo.net"), strings.Contains(sni, "dragons.nintendo.net"):
			backend = dauth
		case strings.Contains(sni, "demonware.net"):
			// L'auth diablo-3 lit l'en-tete PROXY comme les auth NEX
			// (NEXTENDO_PROXY_PROTOCOL=1) : il sert a l'online-check.
			backend, wantProxy = d3, proxyProto
		}
	}
	log.Printf("conn from %s sni=%q -> %s", c.RemoteAddr(), sni, backend)

	up, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("dial %s: %v", backend, err)
		return
	}
	defer up.Close()

	if wantProxy {
		if err := writeProxyHeader(up, c); err != nil {
			return
		}
	}
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

// writeProxyHeader émet l'en-tête PROXY v1 attendu par ListenSecureProxy :
// "PROXY TCP4 <ip client> <ip locale> <port client> <port local>\r\n".
func writeProxyHeader(up, c net.Conn) error {
	src, ok1 := c.RemoteAddr().(*net.TCPAddr)
	dst, ok2 := c.LocalAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return nil
	}
	fam := "TCP4"
	if src.IP.To4() == nil {
		fam = "TCP6"
	}
	_, err := fmt.Fprintf(up, "PROXY %s %s %s %d %d\r\n", fam, src.IP.String(), dst.IP.String(), src.Port, dst.Port)
	return err
}