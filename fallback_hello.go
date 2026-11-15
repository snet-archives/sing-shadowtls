package shadowtls

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	tlsMaxRecordPayload = 16384
	tlsHandshakeHeader  = 4
)

// extractClientHelloFrame reads an initial TLS ClientHello record for ShadowTLS.
// If the incoming bytes are not a valid TLS ClientHello header (e.g., plaintext HTTP
// or random active-probing garbage), it returns immediately with the bytes already
// read and isValidClientHello=false so the caller can fall back without blocking.
func extractClientHelloFrame(conn net.Conn) (*buf.Buffer, bool, error) {
	var tlsHeader [tlsHeaderSize]byte
	n, err := io.ReadFull(conn, tlsHeader[:])
	if err != nil {
		if n > 0 {
			buffer := buf.NewSize(n)
			common.Must1(buffer.Write(tlsHeader[:n]))
			return buffer, false, nil
		}
		return nil, false, err
	}

	length := int(binary.BigEndian.Uint16(tlsHeader[3:]))
	if tlsHeader[0] != handshake || tlsHeader[1] != 0x03 || tlsHeader[2] > 0x04 || length < tlsHandshakeHeader || length > tlsMaxRecordPayload {
		buffer := buf.NewSize(tlsHeaderSize)
		common.Must1(buffer.Write(tlsHeader[:]))
		return buffer, false, nil
	}

	raw := make([]byte, tlsHeaderSize+length)
	copy(raw, tlsHeader[:])
	readLen := tlsHeaderSize
	for readLen < len(raw) {
		rn, rErr := conn.Read(raw[readLen:])
		if rn > 0 {
			readLen += rn
			if readLen >= tlsHeaderSize+tlsHandshakeHeader {
				if raw[tlsHeaderSize] != clientHello {
					buffer := buf.NewSize(readLen)
					common.Must1(buffer.Write(raw[:readLen]))
					return buffer, false, nil
				}
				handshakeLen := int(raw[tlsHeaderSize+1])<<16 | int(raw[tlsHeaderSize+2])<<8 | int(raw[tlsHeaderSize+3])
				if handshakeLen+tlsHandshakeHeader != length {
					buffer := buf.NewSize(readLen)
					common.Must1(buffer.Write(raw[:readLen]))
					return buffer, false, nil
				}
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) && readLen < len(raw) {
				buffer := buf.NewSize(readLen)
				common.Must1(buffer.Write(raw[:readLen]))
				return buffer, false, nil
			}
			return nil, false, rErr
		}
	}

	buffer := buf.NewSize(readLen)
	common.Must1(buffer.Write(raw[:readLen]))
	return buffer, true, nil
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

func unwrapTCPConn(conn net.Conn) *net.TCPConn {
	for conn != nil {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			return tcpConn
		}
		if netConnProvider, ok := conn.(interface{ NetConn() net.Conn }); ok {
			next := netConnProvider.NetConn()
			if next != conn {
				conn = next
				continue
			}
		}
		if upstreamProvider, ok := conn.(interface{ Upstream() any }); ok {
			if next, ok := upstreamProvider.Upstream().(net.Conn); ok && next != conn {
				conn = next
				continue
			}
		}
		break
	}
	return nil
}

func setResetLinger(conn net.Conn) {
	if tcpConn := unwrapTCPConn(conn); tcpConn != nil {
		_ = tcpConn.SetLinger(0)
	}
}

// copyFallbackConn relays an unauthenticated or non-TLS probe directly between
// the client and the handshake server, preserving upstream TCP RST semantics
// without sending a preceding FIN via CloseWrite.
func copyFallbackConn(ctx context.Context, clientConn net.Conn, cachedFrame *buf.Buffer, handshakeConn net.Conn) error {
	cachedConn := bufio.NewCachedConn(clientConn, cachedFrame)
	var resetByUpstream atomic.Bool
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			if resetByUpstream.Load() {
				setResetLinger(clientConn)
			}
			_ = clientConn.Close()
			_ = handshakeConn.Close()
		})
	}
	stopCancel := context.AfterFunc(ctx, closeBoth)
	defer stopCancel()

	var wg sync.WaitGroup
	var c2sErr, s2cErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, c2sErr = io.Copy(handshakeConn, cachedConn)
		if c2sErr == nil {
			_ = N.CloseWrite(handshakeConn)
		} else {
			closeBoth()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, s2cErr = io.Copy(clientConn, handshakeConn)
		if isConnReset(s2cErr) {
			resetByUpstream.Store(true)
			closeBoth()
			return
		}
		if s2cErr == nil {
			_ = N.CloseWrite(clientConn)
			_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		} else {
			closeBoth()
		}
	}()

	wg.Wait()
	closeBoth()
	if s2cErr != nil {
		return s2cErr
	}
	return c2sErr
}
