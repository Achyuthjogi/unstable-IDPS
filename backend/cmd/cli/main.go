package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/rivo/tview"
)

type DashboardData struct {
	System struct {
		CPU               float64 `json:"cpu"`
		Memory            float64 `json:"memory"`
		ActiveConnections int     `json:"active_connections"`
		MLEnabled         bool    `json:"ml_enabled"`
	} `json:"system"`
	Network struct {
		PacketCount     int `json:"packet_count"`
		AlertsCount     int `json:"alerts_count"`
		BlockedIPsCount int `json:"blocked_ips_count"`
	} `json:"network"`
	Alerts []struct {
		Timestamp float64 `json:"timestamp"`
		AlertType string  `json:"alert_type"`
		Severity  string  `json:"severity"`
		SourceIP  string  `json:"source_ip"`
		DestIP    string  `json:"dest_ip"`
		Reason    string  `json:"reason"`
		Action    string  `json:"action"`
	} `json:"alerts"`
	Blocked []struct {
		IP        string `json:"ip"`
		MAC       string `json:"mac"`
		Reason    string `json:"reason"`
	} `json:"blocked"`
	TrafficLog []struct {
		Timestamp float64 `json:"timestamp"`
		SrcIP     string  `json:"src_ip"`
		Domain    string  `json:"domain"`
		Proto     string  `json:"proto"`
	} `json:"traffic_log"`
}

func main() {
	godotenv.Load("../../.env")
	godotenv.Load("../.env")
	godotenv.Load(".env")

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		apiKey = "idps_demo_key"
	}

	app := tview.NewApplication()

	// UI Components
	header := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)

	alertsBox := tview.NewTable().
		SetBorders(false).
		SetSelectable(false, false)
	alertsBox.SetTitle(" 🚨 Live Alerts ").SetBorder(true)

	blockedBox := tview.NewTable().
		SetBorders(false).
		SetSelectable(false, false)
	blockedBox.SetTitle(" 🛑 Blocked Devices ").SetBorder(true)

	trafficBox := tview.NewTable().
		SetBorders(false).
		SetSelectable(false, false)
	trafficBox.SetTitle(" 🌐 Network Traffic ").SetBorder(true)

	grid := tview.NewGrid().
		SetRows(3, 0, 0).
		SetColumns(0, 0).
		SetBorders(true).
		AddItem(header, 0, 0, 1, 2, 0, 0, false).
		AddItem(alertsBox, 1, 0, 1, 2, 0, 0, false).
		AddItem(blockedBox, 2, 0, 1, 1, 0, 0, false).
		AddItem(trafficBox, 2, 1, 1, 1, 0, 0, false)

	go func() {
		for {
			dialer := websocket.Dialer{
				Subprotocols: []string{apiKey},
			}

			wsURL := "ws://localhost:8000/ws"
			conn, _, err := dialer.Dial(wsURL, nil)
			if err != nil {
				app.QueueUpdateDraw(func() {
					header.SetText(fmt.Sprintf("[red]Disconnected - Retrying to connect to backend on %s...[-]", wsURL))
				})
				time.Sleep(2 * time.Second)
				continue
			}

			app.QueueUpdateDraw(func() {
				header.SetText(fmt.Sprintf("[green]Connected to Ultimate IDPS Engine (%s)[-]", wsURL))
			})

			for {
				var data DashboardData
				if err := conn.ReadJSON(&data); err != nil {
					conn.Close()
					break
				}

				app.QueueUpdateDraw(func() {
					// Update Header
					mlStatus := "[red]DISABLED[-]"
					if data.System.MLEnabled {
						mlStatus = "[green]ENABLED[-]"
					}
					
					headerText := fmt.Sprintf(
						"CPU: [yellow]%.1f%%[-] | Mem: [yellow]%.1f%%[-] | Pkts: [cyan]%d[-] | Conns: [cyan]%d[-] | Alerts: [red]%d[-] | Blocks: [red]%d[-] | ML: %s",
						data.System.CPU, data.System.Memory, data.Network.PacketCount,
						data.System.ActiveConnections, data.Network.AlertsCount, data.Network.BlockedIPsCount, mlStatus,
					)
					header.SetText(headerText)

					// Update Alerts
					alertsBox.Clear()
					alertsBox.SetCell(0, 0, tview.NewTableCell("Time").SetTextColor(tcell.ColorYellow))
					alertsBox.SetCell(0, 1, tview.NewTableCell("Type").SetTextColor(tcell.ColorYellow))
					alertsBox.SetCell(0, 2, tview.NewTableCell("Source IP").SetTextColor(tcell.ColorYellow))
					alertsBox.SetCell(0, 3, tview.NewTableCell("Severity").SetTextColor(tcell.ColorYellow))
					alertsBox.SetCell(0, 4, tview.NewTableCell("Reason").SetTextColor(tcell.ColorYellow))
					alertsBox.SetCell(0, 5, tview.NewTableCell("Action").SetTextColor(tcell.ColorYellow))
					
					for i, a := range data.Alerts {
						row := i + 1
						color := tcell.ColorWhite
						if a.Severity == "High" || a.Severity == "Critical" {
							color = tcell.ColorRed
						} else if a.Severity == "Medium" {
							color = tcell.ColorOrange
						}
						
						ts := time.Unix(int64(a.Timestamp), 0).Format("15:04:05")
						alertsBox.SetCell(row, 0, tview.NewTableCell(ts).SetTextColor(color))
						alertsBox.SetCell(row, 1, tview.NewTableCell(a.AlertType).SetTextColor(color))
						alertsBox.SetCell(row, 2, tview.NewTableCell(a.SourceIP).SetTextColor(color))
						alertsBox.SetCell(row, 3, tview.NewTableCell(a.Severity).SetTextColor(color))
						alertsBox.SetCell(row, 4, tview.NewTableCell(a.Reason).SetTextColor(color))
						alertsBox.SetCell(row, 5, tview.NewTableCell(a.Action).SetTextColor(color))
					}

					// Update Blocked Box
					blockedBox.Clear()
					blockedBox.SetCell(0, 0, tview.NewTableCell("IP").SetTextColor(tcell.ColorYellow))
					blockedBox.SetCell(0, 1, tview.NewTableCell("MAC").SetTextColor(tcell.ColorYellow))
					blockedBox.SetCell(0, 2, tview.NewTableCell("Reason").SetTextColor(tcell.ColorYellow))

					for i, b := range data.Blocked {
						row := i + 1
						blockedBox.SetCell(row, 0, tview.NewTableCell(b.IP).SetTextColor(tcell.ColorRed))
						blockedBox.SetCell(row, 1, tview.NewTableCell(b.MAC).SetTextColor(tcell.ColorRed))
						blockedBox.SetCell(row, 2, tview.NewTableCell(b.Reason).SetTextColor(tcell.ColorRed))
					}

					// Update Traffic Log
					trafficBox.Clear()
					trafficBox.SetCell(0, 0, tview.NewTableCell("Time").SetTextColor(tcell.ColorYellow))
					trafficBox.SetCell(0, 1, tview.NewTableCell("Proto").SetTextColor(tcell.ColorYellow))
					trafficBox.SetCell(0, 2, tview.NewTableCell("Source IP").SetTextColor(tcell.ColorYellow))
					trafficBox.SetCell(0, 3, tview.NewTableCell("Domain").SetTextColor(tcell.ColorYellow))

					for i, t := range data.TrafficLog {
						row := i + 1
						ts := time.Unix(int64(t.Timestamp), 0).Format("15:04:05")
						trafficBox.SetCell(row, 0, tview.NewTableCell(ts).SetTextColor(tcell.ColorWhite))
						trafficBox.SetCell(row, 1, tview.NewTableCell(t.Proto).SetTextColor(tcell.ColorTeal))
						trafficBox.SetCell(row, 2, tview.NewTableCell(t.SrcIP).SetTextColor(tcell.ColorGreen))
						trafficBox.SetCell(row, 3, tview.NewTableCell(t.Domain).SetTextColor(tcell.ColorWhite))
					}
				})
			}
		}
	}()

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC || event.Key() == tcell.KeyEscape {
			app.Stop()
			return nil
		}
		return event
	})

	if err := app.SetRoot(grid, true).EnableMouse(true).Run(); err != nil {
		log.Fatalf("Error running application: %s", err)
	}
}
