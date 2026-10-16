//go:build windows

package capture

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"sync"
	"time"

	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/platform"
	"idps-backend/state"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
)

func startPlatformCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	return StartWindowsCapture(st, cfg, fm, engines)
}

// StartWindowsCapture initializes packet capture on Windows using raw socket or Npcap adapter.
func StartWindowsCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	pInfo := platform.GetInfo()
	if !pInfo.IsElevated {
		return nil, fmt.Errorf("Windows packet capture failed: Process is not running as Administrator. Please launch terminal/service with 'Run as administrator'")
	}

	workerCount := len(engines)
	if workerCount <= 0 {
		return nil, fmt.Errorf("no detection engines provided")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	fmt.Printf("Capture Engine: Starting Windows Network Adapter (%s) with %d workers\n", pInfo.DriverName, workerCount)

	// Dispatch worker helper
	getEngine := func(srcIP, dstIP string, srcPort, dstPort uint16) *detection.Engine {
		if workerCount == 1 {
			return engines[0]
		}
		hash := fnv.New32a()
		hash.Write([]byte(srcIP))
		hash.Write([]byte(dstIP))
		var portBuf [4]byte
		portBuf[0] = byte(srcPort >> 8)
		portBuf[1] = byte(srcPort)
		portBuf[2] = byte(dstPort >> 8)
		portBuf[3] = byte(dstPort)
		hash.Write(portBuf[:])
		idx := int(hash.Sum32()) % workerCount
		return engines[idx]
	}

	// Create Windows Raw Socket for IP-level packet capture
	sock, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		cancel()
		if !pInfo.HasPacketDriver {
			return nil, fmt.Errorf("Windows raw socket capture failed (%v). Npcap driver not detected. Please install Npcap from https://npcap.com with 'Install Npcap in WinPcap API-compatible Mode' enabled", err)
		}
		return nil, fmt.Errorf("failed to open raw socket on Windows: %w", err)
	}

	// Bind to local IP if possible or INADDR_ANY
	var bindIP [4]byte
	if cfg.GatewayIP != "" {
		if parsed := net.ParseIP(cfg.GatewayIP).To4(); parsed != nil {
			copy(bindIP[:], parsed)
		}
	}

	sa := &windows.SockaddrInet4{
		Port: 0,
		Addr: bindIP,
	}

	if err := windows.Bind(sock, sa); err != nil {
		// Fallback to INADDR_ANY (0.0.0.0)
		sa.Addr = [4]byte{0, 0, 0, 0}
		_ = windows.Bind(sock, sa)
	}

	// Enable SIO_RCVALL ioctl on Windows to receive all incoming IPv4 packets
	const SIO_RCVALL = 0x98000001
	inBuf := make([]byte, 4)
	inBuf[0] = 1
	var bytesReturned uint32
	_ = windows.WSAIoctl(sock, SIO_RCVALL, &inBuf[0], 4, nil, 0, &bytesReturned, nil, 0)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer windows.Closesocket(sock)

		buf := make([]byte, 65535)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, _, err := windows.Recvfrom(sock, buf, 0)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}

			if n <= 0 {
				continue
			}

			data := make([]byte, n)
			copy(data, buf[:n])

			// Decode packet starting from IPv4 layer
			packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
			if packet == nil || packet.NetworkLayer() == nil {
				continue
			}

			ts := getTimestamp()
			pktInfo := ParsePacket(packet, st, ts)
			targetEngine := getEngine(pktInfo.SrcIP, pktInfo.DstIP, pktInfo.SrcPort, pktInfo.DstPort)
			targetEngine.ProcessPacket(pktInfo)
		}
	}()

	cleanup := func() {
		cancel()
		windows.Closesocket(sock)
		wg.Wait()
	}

	return cleanup, nil
}
