//go:build linux

package capture

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"idps-backend/config"
	"idps-backend/detection"
	"idps-backend/firewall"
	"idps-backend/state"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

func startPlatformCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	cfg.Mu.RLock()
	secMode := cfg.IDPSSecurityMode
	depMode := cfg.IDPSDeploymentMode
	cfg.Mu.RUnlock()

	// If in inline IPS mode on Linux and not in passive deployment, use NFQueue
	if secMode == "IPS" && depMode != "PASSIVE" {
		fmt.Println("Capture Engine: Starting Linux Netfilter Queue (Inline IPS)")
		return StartNFQueue(st, cfg, fm, engines)
	}

	fmt.Println("Capture Engine: Starting Linux AF_PACKET Zero-Copy Ring (Passive Sniffing)")
	return StartAFPacketCapture(st, cfg, fm, engines)
}

// StartAFPacketCapture starts Linux AF_PACKET ring buffer capture with fanout hashing.
func StartAFPacketCapture(st *state.AppState, cfg *config.Config, fm *firewall.FirewallManager, engines []*detection.Engine) (func(), error) {
	ifaceName := cfg.CaptureInterface
	workerCount := len(engines)
	if workerCount <= 0 {
		return nil, fmt.Errorf("no detection engines provided")
	}

	fanoutGroup := 99 // Arbitrary group ID for fanout

	var handles []*afpacket.TPacket
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < workerCount; i++ {
		handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(ifaceName),
			afpacket.OptFrameSize(4096),
			afpacket.OptBlockSize(4096*128),
			afpacket.OptNumBlocks(128),
			afpacket.OptPollTimeout(1*time.Second),
			afpacket.OptTPacketVersion(afpacket.TPacketVersion2),
		)
		if err != nil {
			for _, h := range handles {
				h.Close()
			}
			cancel()
			return nil, fmt.Errorf("failed to open afpacket on %s: %w", ifaceName, err)
		}

		err = handle.SetFanout(afpacket.FanoutHash, uint16(fanoutGroup))
		if err != nil {
			for _, h := range handles {
				h.Close()
			}
			handle.Close()
			cancel()
			return nil, fmt.Errorf("failed to set fanout hash: %w", err)
		}

		handles = append(handles, handle)
	}

	for i := 0; i < workerCount; i++ {
		handle := handles[i]
		engine := engines[i]

		wg.Add(1)
		go func(workerID int, h *afpacket.TPacket, eng *detection.Engine) {
			defer wg.Done()
			source := gopacket.NewPacketSource(h, layers.LinkTypeEthernet)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				packet, err := source.NextPacket()
				if err != nil {
					if strings.Contains(err.Error(), "timeout") || err.Error() == "Timeout Expired" {
						continue
					}
					select {
					case <-ctx.Done():
						return
					default:
						time.Sleep(10 * time.Millisecond)
						continue
					}
				}

				if packet == nil {
					continue
				}

				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Printf("worker %d: recovered from panic while processing packet: %v\n", workerID, r)
						}
					}()

					ts := getTimestamp()
					pktInfo := ParsePacket(packet, st, ts)
					eng.ProcessPacket(pktInfo)
				}()
			}
		}(i, handle, engine)
	}

	cleanup := func() {
		cancel()
		for _, h := range handles {
			h.Close()
		}
		wg.Wait()
	}

	return cleanup, nil
}
