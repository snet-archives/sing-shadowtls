package shadowtls

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type probeNoopHandler struct{}

func (h *probeNoopHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
}

func startShadowTLSProbeFixture(t *testing.T, upstreamHandler func(net.Conn)) net.Addr {
	t.Helper()
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstreamLn.Close() })
	go func() {
		for {
			c, aErr := upstreamLn.Accept()
			if aErr != nil {
				return
			}
			go upstreamHandler(c)
		}
	}()

	svc, err := NewService(ServiceConfig{
		Version:  3,
		Password: "probe-password",
		Users:    []User{{Name: "test", Password: "probe-password"}},
		Handshake: HandshakeConfig{
			Dialer: N.SystemDialer,
			Server: M.ParseSocksaddr(upstreamLn.Addr().String()),
		},
		Handler: &probeNoopHandler{},
		Logger:  logger.NOP(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	svcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen service: %v", err)
	}
	t.Cleanup(func() { _ = svcLn.Close() })
	go func() {
		for {
			c, aErr := svcLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				_ = svc.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), M.Socksaddr{}, nil)
			}(c)
		}
	}()
	return svcLn.Addr()
}

func TestServiceV3NonTLSProbeFastFallbackAndResetPropagation(t *testing.T) {
	probes := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "http_get_length_oracle_0x202f",
			payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:    "random_16b_non_tls",
			payload: []byte{0x9f, 0x11, 0x7a, 0x3b, 0x42, 0x09, 0xe8, 0x55, 0x61, 0x7c, 0x99, 0x02, 0xaa, 0x10, 0x43, 0xef},
		},
		{
			name:    "bad_handshake_type_inside_tls_record",
			payload: []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x47, 0x45, 0x54, 0x20, 0x2f},
		},
	}

	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan []byte, 1)
			addr := startShadowTLSProbeFixture(t, func(c net.Conn) {
				buf := make([]byte, 256)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				n, _ := c.Read(buf)
				if n > 0 {
					cp := make([]byte, n)
					copy(cp, buf[:n])
					select {
					case received <- cp:
					default:
					}
				}
				if tcpConn, ok := c.(*net.TCPConn); ok {
					_ = tcpConn.SetLinger(0)
				}
				_ = c.Close()
			})

			start := time.Now()
			client, err := net.DialTimeout("tcp", addr.String(), time.Second)
			if err != nil {
				t.Fatalf("dial service: %v", err)
			}
			defer client.Close()
			if _, err := client.Write(tc.payload); err != nil {
				t.Fatalf("write probe: %v", err)
			}

			var out [64]byte
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			_, readErr := client.Read(out[:])
			elapsed := time.Since(start)
			if elapsed > 300*time.Millisecond {
				t.Fatalf("non-TLS probe blocked too long: %v", elapsed)
			}
			if !errors.Is(readErr, syscall.ECONNRESET) && !errors.Is(readErr, io.EOF) {
				t.Fatalf("expected ECONNRESET or EOF, got %v", readErr)
			}
			if !errors.Is(readErr, syscall.ECONNRESET) {
				t.Fatalf("expected upstream TCP RST propagation (ECONNRESET), got %v", readErr)
			}

			select {
			case got := <-received:
				if len(got) == 0 {
					t.Fatalf("expected upstream to receive forwarded bytes")
				}
			case <-time.After(time.Second):
				t.Fatalf("upstream did not receive forwarded probe")
			}
		})
	}
}
