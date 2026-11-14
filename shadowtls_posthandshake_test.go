package shadowtls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testTCPHandler struct {
	onConn func(ctx context.Context, conn net.Conn)
}

func (h *testTCPHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	if onClose != nil {
		defer onClose(nil)
	}
	h.onConn(ctx, conn)
}

type appFrameCounterDialer struct {
	net.Dialer
	appFrames atomic.Int32
}

type appFrameCountingConn struct {
	net.Conn
	buf       []byte
	appFrames *atomic.Int32
}

func (c *appFrameCountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
		for len(c.buf) >= tlsHeaderSize {
			recLen := int(binary.BigEndian.Uint16(c.buf[3:tlsHeaderSize]))
			total := tlsHeaderSize + recLen
			if len(c.buf) < total {
				break
			}
			if c.buf[0] == applicationData {
				c.appFrames.Add(1)
			}
			c.buf = c.buf[total:]
		}
	}
	return n, err
}

func (d *appFrameCounterDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	return &appFrameCountingConn{Conn: conn, appFrames: &d.appFrames}, nil
}

func (d *appFrameCounterDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func generateShadowTLSTestCert(t *testing.T, serverName string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestServiceV3ForwardsDelayedPostHandshakeTickets(t *testing.T) {
	const (
		serverName = "example.com"
		password   = "secret-pass"
	)
	cert := generateShadowTLSTestCert(t, serverName)

	// Mock TLS 1.3 handshake target that sleeps briefly after Handshake() and emits
	// an extra TLS 1.3 NewSessionTicket-shaped ApplicationData record before closing.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var backendWG sync.WaitGroup
	defer func() {
		backendLn.Close()
		backendWG.Wait()
	}()

	backendWG.Add(1)
	go func() {
		defer backendWG.Done()
		for {
			rawConn, err := backendLn.Accept()
			if err != nil {
				return
			}
			backendWG.Add(1)
			go func(conn net.Conn) {
				defer backendWG.Done()
				defer conn.Close()
				tlsConn := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS13,
					MaxVersion:   tls.VersionTLS13,
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				time.Sleep(35 * time.Millisecond)
				delayedTicket := make([]byte, tlsHeaderSize+48)
				delayedTicket[0] = applicationData
				delayedTicket[1] = 0x03
				delayedTicket[2] = 0x03
				binary.BigEndian.PutUint16(delayedTicket[3:tlsHeaderSize], 48)
				_, _ = conn.Write(delayedTicket)
				time.Sleep(30 * time.Millisecond)
			}(rawConn)
		}
	}()

	backendAddr := M.ParseSocksaddr(backendLn.Addr().String())
	handlerErr := make(chan error, 1)
	service, err := NewService(ServiceConfig{
		Version: 3,
		Users:   []User{{Name: "u1", Password: password}},
		Handshake: HandshakeConfig{
			Server: backendAddr,
			Dialer: N.SystemDialer,
		},
		StrictMode: true,
		Handler: &testTCPHandler{
			onConn: func(ctx context.Context, conn net.Conn) {
				defer conn.Close()
				req := make([]byte, 5)
				if _, err := io.ReadFull(conn, req); err != nil {
					handlerErr <- err
					return
				}
				if !bytes.Equal(req, []byte("hello")) {
					handlerErr <- io.ErrUnexpectedEOF
					return
				}
				_, err := conn.Write([]byte("world"))
				handlerErr <- err
			},
		},
		Logger: logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}

	serviceLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serviceLn.Close()

	serviceErr := make(chan error, 1)
	go func() {
		conn, err := serviceLn.Accept()
		if err != nil {
			serviceErr <- err
			return
		}
		defer conn.Close()
		serviceErr <- service.NewConnection(context.Background(), conn, M.Socksaddr{}, M.Socksaddr{}, nil)
	}()

	dialer := &appFrameCounterDialer{}
	client, err := NewClient(ClientConfig{
		Version:      3,
		Password:     password,
		Server:       M.ParseSocksaddr(serviceLn.Addr().String()),
		Dialer:       dialer,
		StrictMode:   true,
		TLSHandshake: DefaultTLSHandshakeFunc(password, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}),
		Logger:       logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cConn, err := client.DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()

	// Send first proxy frame right after TLS handshake (triggers handshakeFinished on server).
	if _, err := cConn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	framesAfterHandshake := dialer.appFrames.Load()

	reply := make([]byte, 5)
	if _, err := io.ReadFull(cConn, reply); err != nil {
		t.Fatalf("read server reply after delayed ticket: %v", err)
	}
	if !bytes.Equal(reply, []byte("world")) {
		t.Fatalf("expected world, got %q", reply)
	}
	framesAfterReply := dialer.appFrames.Load()
	// Expect at least 2 extra applicationData frames after initial handshake:
	// 1 delayed NewSessionTicket forwarded with hmacWrite + 1 "world" reply with hmacAdd.
	if framesAfterReply < framesAfterHandshake+2 {
		t.Fatalf("expected delayed NewSessionTicket + reply frames (before=%d, after=%d)", framesAfterHandshake, framesAfterReply)
	}

	if err := <-handlerErr; err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if err := <-serviceErr; err != nil {
		t.Fatalf("service err: %v", err)
	}
}
