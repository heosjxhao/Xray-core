//go:build android

package tlsspoof

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

const PlatformSupported = true

const (
	tcpRecvQueue = 1
	tcpSendQueue = 2
)

type androidSpoofer struct {
	method      Method
	src         netip.AddrPort
	dst         netip.AddrPort
	rawFD       int
	rawSockAddr unix.Sockaddr
	sendNext    uint32
	receiveNext uint32
	timestamp   uint32
}

func newRawSpoofer(conn net.Conn, method Method) (rawSpoofer, error) {
	tcpConn, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	fd, sockaddr, err := openAndroidRawSocket(dst)
	if err != nil {
		return nil, err
	}
	spoofer := &androidSpoofer{
		method:      method,
		src:         src,
		dst:         dst,
		rawFD:       fd,
		rawSockAddr: sockaddr,
	}
	if err = spoofer.loadSequenceNumbers(tcpConn); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return spoofer, nil
}

func openAndroidRawSocket(dst netip.AddrPort) (int, unix.Sockaddr, error) {
	if dst.Addr().Is4() {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
		if err != nil {
			return -1, nil, fmt.Errorf("tls_spoof: open AF_INET SOCK_RAW (Android root/CAP_NET_RAW required): %w", err)
		}
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			unix.Close(fd)
			return -1, nil, fmt.Errorf("tls_spoof: set IP_HDRINCL: %w", err)
		}
		return fd, &unix.SockaddrInet4{Addr: dst.Addr().As4()}, nil
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, nil, fmt.Errorf("tls_spoof: open AF_INET6 SOCK_RAW (Android root/CAP_NET_RAW required): %w", err)
	}
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return -1, nil, fmt.Errorf("tls_spoof: set IPV6_HDRINCL: %w", err)
	}
	return fd, &unix.SockaddrInet6{Addr: dst.Addr().As16()}, nil
}

func (s *androidSpoofer) loadSequenceNumbers(tcpConn *net.TCPConn) error {
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}
	var ctrlErr error
	err = rawConn.Control(func(raw uintptr) {
		fd := int(raw)

		if s.method == MethodWrongTimestamp {
			timestamp, tsErr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
			if tsErr != nil {
				ctrlErr = fmt.Errorf("tls_spoof: read timestamp: %w", tsErr)
				return
			}
			s.timestamp = uint32(timestamp)
		}

		ctrlErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
		if ctrlErr != nil {
			ctrlErr = fmt.Errorf("tls_spoof: enter TCP_REPAIR (Android root/CAP_NET_ADMIN required): %w", ctrlErr)
			return
		}
		defer func() {
			offErr := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF)
			if offErr != nil {
				offErr = fmt.Errorf("tls_spoof: leave TCP_REPAIR: %w", offErr)
				if ctrlErr == nil {
					ctrlErr = offErr
				} else {
					ctrlErr = fmt.Errorf("%v; also %w", ctrlErr, offErr)
				}
			}
		}()

		ctrlErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpSendQueue)
		if ctrlErr != nil {
			ctrlErr = fmt.Errorf("tls_spoof: select TCP_SEND_QUEUE: %w", ctrlErr)
			return
		}
		sendSequence, seqErr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if seqErr != nil {
			ctrlErr = fmt.Errorf("tls_spoof: read send queue sequence: %w", seqErr)
			return
		}
		ctrlErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRecvQueue)
		if ctrlErr != nil {
			ctrlErr = fmt.Errorf("tls_spoof: select TCP_RECV_QUEUE: %w", ctrlErr)
			return
		}
		receiveSequence, seqErr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if seqErr != nil {
			ctrlErr = fmt.Errorf("tls_spoof: read recv queue sequence: %w", seqErr)
			return
		}
		s.sendNext = uint32(sendSequence)
		s.receiveNext = uint32(receiveSequence)
	})
	if err != nil {
		return err
	}
	return ctrlErr
}

func (s *androidSpoofer) Inject(payload []byte) error {
	frame, err := buildSpoofFrame(s.method, s.src, s.dst, s.sendNext, s.receiveNext, s.timestamp, nil, payload)
	if err != nil {
		return err
	}
	if err = unix.Sendto(s.rawFD, frame, 0, s.rawSockAddr); err != nil {
		return fmt.Errorf("tls_spoof: sendto raw socket: %w", err)
	}
	return nil
}

func (s *androidSpoofer) Close() error {
	if s.rawFD < 0 {
		return nil
	}
	err := unix.Close(s.rawFD)
	s.rawFD = -1
	return err
}
