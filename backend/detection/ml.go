package detection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"idps-backend/flow"
)

// MLClient handles communication with the Python ML inference service.
type MLClient struct {
	endpoint   string
	httpClient *http.Client
	available  bool
}

// NewMLClient creates a new ML client targeting the given base URL.
func NewMLClient(baseURL string) *MLClient {
	c := &MLClient{
		endpoint: baseURL,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}
	// Check initial availability
	c.available = c.HealthCheck()
	return c
}

// HealthCheck pings the ML service /health endpoint.
func (c *MLClient) HealthCheck() bool {
	resp, err := c.httpClient.Get(c.endpoint + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// IsAvailable returns whether the ML service was reachable at last check.
func (c *MLClient) IsAvailable() bool {
	return c.available
}

// RefreshAvailability re-checks if the ML service is up.
func (c *MLClient) RefreshAvailability() {
	c.available = c.HealthCheck()
}

// FlowFeatures holds the 78 CIC-IDS-2017 features sent to the ML service.
type FlowFeatures struct {
	DestinationPort       float64 `json:"destination_port"`
	FlowDuration          float64 `json:"flow_duration"`
	TotalFwdPackets       float64 `json:"total_fwd_packets"`
	TotalBackwardPackets  float64 `json:"total_backward_packets"`
	TotalLenFwdPackets    float64 `json:"total_length_of_fwd_packets"`
	TotalLenBwdPackets    float64 `json:"total_length_of_bwd_packets"`
	FwdPktLenMax          float64 `json:"fwd_packet_length_max"`
	FwdPktLenMin          float64 `json:"fwd_packet_length_min"`
	FwdPktLenMean         float64 `json:"fwd_packet_length_mean"`
	FwdPktLenStd          float64 `json:"fwd_packet_length_std"`
	BwdPktLenMax          float64 `json:"bwd_packet_length_max"`
	BwdPktLenMin          float64 `json:"bwd_packet_length_min"`
	BwdPktLenMean         float64 `json:"bwd_packet_length_mean"`
	BwdPktLenStd          float64 `json:"bwd_packet_length_std"`
	FlowBytesPerS         float64 `json:"flow_bytes_per_s"`
	FlowPacketsPerS       float64 `json:"flow_packets_per_s"`
	FlowIATMean           float64 `json:"flow_iat_mean"`
	FlowIATStd            float64 `json:"flow_iat_std"`
	FlowIATMax            float64 `json:"flow_iat_max"`
	FlowIATMin            float64 `json:"flow_iat_min"`
	FwdIATTotal           float64 `json:"fwd_iat_total"`
	FwdIATMean            float64 `json:"fwd_iat_mean"`
	FwdIATStd             float64 `json:"fwd_iat_std"`
	FwdIATMax             float64 `json:"fwd_iat_max"`
	FwdIATMin             float64 `json:"fwd_iat_min"`
	BwdIATTotal           float64 `json:"bwd_iat_total"`
	BwdIATMean            float64 `json:"bwd_iat_mean"`
	BwdIATStd             float64 `json:"bwd_iat_std"`
	BwdIATMax             float64 `json:"bwd_iat_max"`
	BwdIATMin             float64 `json:"bwd_iat_min"`
	FwdPSHFlags           float64 `json:"fwd_psh_flags"`
	BwdPSHFlags           float64 `json:"bwd_psh_flags"`
	FwdURGFlags           float64 `json:"fwd_urg_flags"`
	BwdURGFlags           float64 `json:"bwd_urg_flags"`
	FwdHeaderLength       float64 `json:"fwd_header_length"`
	BwdHeaderLength       float64 `json:"bwd_header_length"`
	FwdPacketsPerS        float64 `json:"fwd_packets_per_s"`
	BwdPacketsPerS        float64 `json:"bwd_packets_per_s"`
	MinPacketLength       float64 `json:"min_packet_length"`
	MaxPacketLength       float64 `json:"max_packet_length"`
	PacketLengthMean      float64 `json:"packet_length_mean"`
	PacketLengthStd       float64 `json:"packet_length_std"`
	PacketLengthVariance  float64 `json:"packet_length_variance"`
	FINFlagCount          float64 `json:"fin_flag_count"`
	SYNFlagCount          float64 `json:"syn_flag_count"`
	RSTFlagCount          float64 `json:"rst_flag_count"`
	PSHFlagCount          float64 `json:"psh_flag_count"`
	ACKFlagCount          float64 `json:"ack_flag_count"`
	URGFlagCount          float64 `json:"urg_flag_count"`
	CWEFlagCount          float64 `json:"cwe_flag_count"`
	ECEFlagCount          float64 `json:"ece_flag_count"`
	DownUpRatio           float64 `json:"down_up_ratio"`
	AveragePacketSize     float64 `json:"average_packet_size"`
	AvgFwdSegmentSize     float64 `json:"avg_fwd_segment_size"`
	AvgBwdSegmentSize     float64 `json:"avg_bwd_segment_size"`
	FwdHeaderLength1      float64 `json:"fwd_header_length_1"`
	FwdAvgBytesPerBulk    float64 `json:"fwd_avg_bytes_per_bulk"`
	FwdAvgPacketsPerBulk  float64 `json:"fwd_avg_packets_per_bulk"`
	FwdAvgBulkRate        float64 `json:"fwd_avg_bulk_rate"`
	BwdAvgBytesPerBulk    float64 `json:"bwd_avg_bytes_per_bulk"`
	BwdAvgPacketsPerBulk  float64 `json:"bwd_avg_packets_per_bulk"`
	BwdAvgBulkRate        float64 `json:"bwd_avg_bulk_rate"`
	SubflowFwdPackets     float64 `json:"subflow_fwd_packets"`
	SubflowFwdBytes       float64 `json:"subflow_fwd_bytes"`
	SubflowBwdPackets     float64 `json:"subflow_bwd_packets"`
	SubflowBwdBytes       float64 `json:"subflow_bwd_bytes"`
	InitWinBytesForward   float64 `json:"init_win_bytes_forward"`
	InitWinBytesBackward  float64 `json:"init_win_bytes_backward"`
	ActDataPktFwd         float64 `json:"act_data_pkt_fwd"`
	MinSegSizeForward     float64 `json:"min_seg_size_forward"`
	ActiveMean            float64 `json:"active_mean"`
	ActiveStd             float64 `json:"active_std"`
	ActiveMax             float64 `json:"active_max"`
	ActiveMin             float64 `json:"active_min"`
	IdleMean              float64 `json:"idle_mean"`
	IdleStd               float64 `json:"idle_std"`
	IdleMax               float64 `json:"idle_max"`
	IdleMin               float64 `json:"idle_min"`
}

// MLResponse is the prediction result from the ML service.
type MLResponse struct {
	Malicious  bool    `json:"malicious"`
	Prediction string  `json:"prediction"`
	Confidence float64 `json:"confidence"`
}

// safeRate returns numerator/durationS, or 0 if durationS is not positive —
// avoids astronomically large rate values for near-instant flows.
func safeRate(numerator, durationS float64) float64 {
	if durationS <= 0 {
		return 0
	}
	return numerator / durationS
}

// ExtractFlowFeatures computes the 78 CIC-IDS-2017 features from a tracked flow.
// The flow's Mu must NOT be held when calling this function.
func ExtractFlowFeatures(f *flow.Flow, dstPort uint16) FlowFeatures {
	f.Mu.Lock()
	defer f.Mu.Unlock()

	durationUs := float64(f.LastSeen.Sub(f.CreatedAt).Microseconds())
	if durationUs < 0 {
		durationUs = 0
	}
	durationS := durationUs / 1e6

	totalPackets := f.FwdPacketCount + f.BwdPacketCount
	totalBytes := f.FwdByteCount + f.BwdByteCount

	fwdLens := flow.IntSliceToFloat(f.FwdPacketLengths)
	bwdLens := flow.IntSliceToFloat(f.BwdPacketLengths)
	allLens := append(append([]float64{}, fwdLens...), bwdLens...)

	var downUpRatio float64
	if f.FwdPacketCount > 0 {
		downUpRatio = float64(f.BwdPacketCount) / float64(f.FwdPacketCount)
	}

	var avgPktSize float64
	if totalPackets > 0 {
		avgPktSize = float64(totalBytes) / float64(totalPackets)
	}

	var avgFwdSeg, avgBwdSeg float64
	if f.FwdPacketCount > 0 {
		avgFwdSeg = float64(f.FwdByteCount) / float64(f.FwdPacketCount)
	}
	if f.BwdPacketCount > 0 {
		avgBwdSeg = float64(f.BwdByteCount) / float64(f.BwdPacketCount)
	}

	pktLenStd := flow.SliceStd(allLens)

	// ── Bulk features: include the in-progress run if it already
	// qualifies (≥4 data packets), without mutating flow state. ──────────
	fwdBulkBytes, fwdBulkPackets, fwdBulkDurUs, fwdBulkCount := f.FwdBulkBytes, f.FwdBulkPackets, f.FwdBulkDurationUs, f.FwdBulkCount
	if f.FwdBulkRunPackets >= 4 {
		fwdBulkBytes += f.FwdBulkRunBytes
		fwdBulkPackets += f.FwdBulkRunPackets
		fwdBulkDurUs += float64(f.FwdBulkRunEnd.Sub(f.FwdBulkRunStart).Microseconds())
		fwdBulkCount++
	}
	bwdBulkBytes, bwdBulkPackets, bwdBulkDurUs, bwdBulkCount := f.BwdBulkBytes, f.BwdBulkPackets, f.BwdBulkDurationUs, f.BwdBulkCount
	if f.BwdBulkRunPackets >= 4 {
		bwdBulkBytes += f.BwdBulkRunBytes
		bwdBulkPackets += f.BwdBulkRunPackets
		bwdBulkDurUs += float64(f.BwdBulkRunEnd.Sub(f.BwdBulkRunStart).Microseconds())
		bwdBulkCount++
	}

	var fwdAvgBytesPerBulk, fwdAvgPacketsPerBulk, fwdAvgBulkRate float64
	if fwdBulkCount > 0 {
		fwdAvgBytesPerBulk = float64(fwdBulkBytes) / float64(fwdBulkCount)
		fwdAvgPacketsPerBulk = float64(fwdBulkPackets) / float64(fwdBulkCount)
		fwdAvgBulkRate = safeRate(float64(fwdBulkBytes), fwdBulkDurUs/1e6)
	}
	var bwdAvgBytesPerBulk, bwdAvgPacketsPerBulk, bwdAvgBulkRate float64
	if bwdBulkCount > 0 {
		bwdAvgBytesPerBulk = float64(bwdBulkBytes) / float64(bwdBulkCount)
		bwdAvgPacketsPerBulk = float64(bwdBulkPackets) / float64(bwdBulkCount)
		bwdAvgBulkRate = safeRate(float64(bwdBulkBytes), bwdBulkDurUs/1e6)
	}

	// ── Active/idle features: include the currently open active period
	// as if it closed now, without mutating flow state. ──────────────────
	activePeriods := append([]float64{}, f.ActivePeriods...)
	if !f.ActiveEnd.IsZero() {
		activePeriods = append(activePeriods, float64(f.ActiveEnd.Sub(f.ActiveStart).Microseconds()))
	}
	idlePeriods := f.IdlePeriods

	// Copy IAT slices to avoid data race after unlock
	fwdIATs := make([]float64, len(f.FwdIATs))
	copy(fwdIATs, f.FwdIATs)
	bwdIATs := make([]float64, len(f.BwdIATs))
	copy(bwdIATs, f.BwdIATs)
	allIATs := make([]float64, len(f.AllIATs))
	copy(allIATs, f.AllIATs)

	// Determine the destination port — use the provided dstPort
	dp := float64(dstPort)

	// Initial window sizes
	var initWinFwd, initWinBwd float64
	if f.InitWinFwdSet {
		initWinFwd = float64(f.InitWinFwd)
	}
	if f.InitWinBwdSet {
		initWinBwd = float64(f.InitWinBwd)
	}

	return FlowFeatures{
		DestinationPort:      dp,
		FlowDuration:         durationUs,
		TotalFwdPackets:      float64(f.FwdPacketCount),
		TotalBackwardPackets: float64(f.BwdPacketCount),
		TotalLenFwdPackets:   float64(f.FwdByteCount),
		TotalLenBwdPackets:   float64(f.BwdByteCount),
		FwdPktLenMax:         flow.SliceMax(fwdLens),
		FwdPktLenMin:         flow.SliceMin(fwdLens),
		FwdPktLenMean:        flow.SliceMean(fwdLens),
		FwdPktLenStd:         flow.SliceStd(fwdLens),
		BwdPktLenMax:         flow.SliceMax(bwdLens),
		BwdPktLenMin:         flow.SliceMin(bwdLens),
		BwdPktLenMean:        flow.SliceMean(bwdLens),
		BwdPktLenStd:         flow.SliceStd(bwdLens),
		FlowBytesPerS:        safeRate(float64(totalBytes), durationS),
		FlowPacketsPerS:      safeRate(float64(totalPackets), durationS),
		FlowIATMean:          flow.SliceMean(allIATs),
		FlowIATStd:           flow.SliceStd(allIATs),
		FlowIATMax:           flow.SliceMax(allIATs),
		FlowIATMin:           flow.SliceMin(allIATs),
		FwdIATTotal:          flow.SliceSum(fwdIATs),
		FwdIATMean:           flow.SliceMean(fwdIATs),
		FwdIATStd:            flow.SliceStd(fwdIATs),
		FwdIATMax:            flow.SliceMax(fwdIATs),
		FwdIATMin:            flow.SliceMin(fwdIATs),
		BwdIATTotal:          flow.SliceSum(bwdIATs),
		BwdIATMean:           flow.SliceMean(bwdIATs),
		BwdIATStd:            flow.SliceStd(bwdIATs),
		BwdIATMax:            flow.SliceMax(bwdIATs),
		BwdIATMin:            flow.SliceMin(bwdIATs),
		FwdPSHFlags:          float64(f.FwdPSHFlags),
		BwdPSHFlags:          float64(f.BwdPSHFlags),
		FwdURGFlags:          float64(f.FwdURGFlags),
		BwdURGFlags:          float64(f.BwdURGFlags),
		FwdHeaderLength:      float64(f.FwdHeaderLen),
		BwdHeaderLength:      float64(f.BwdHeaderLen),
		FwdPacketsPerS:       safeRate(float64(f.FwdPacketCount), durationS),
		BwdPacketsPerS:       safeRate(float64(f.BwdPacketCount), durationS),
		MinPacketLength:      flow.SliceMin(allLens),
		MaxPacketLength:      flow.SliceMax(allLens),
		PacketLengthMean:     flow.SliceMean(allLens),
		PacketLengthStd:      pktLenStd,
		PacketLengthVariance: pktLenStd * pktLenStd,
		FINFlagCount:         float64(f.FINCount),
		SYNFlagCount:         float64(f.SYNCount),
		RSTFlagCount:         float64(f.RSTCount),
		PSHFlagCount:         float64(f.PSHCount),
		ACKFlagCount:         float64(f.ACKCount),
		URGFlagCount:         float64(f.URGCount),
		DownUpRatio:          downUpRatio,
		AveragePacketSize:    avgPktSize,
		AvgFwdSegmentSize:    avgFwdSeg,
		AvgBwdSegmentSize:    avgBwdSeg,
		FwdHeaderLength1:     float64(f.FwdHeaderLen),
		SubflowFwdPackets:    float64(f.FwdPacketCount),
		SubflowFwdBytes:      float64(f.FwdByteCount),
		SubflowBwdPackets:    float64(f.BwdPacketCount),
		SubflowBwdBytes:      float64(f.BwdByteCount),
		InitWinBytesForward:  initWinFwd,
		InitWinBytesBackward: initWinBwd,
		ActDataPktFwd:        float64(f.ActDataPktFwd),
		FwdAvgBytesPerBulk:   fwdAvgBytesPerBulk,
		FwdAvgPacketsPerBulk: fwdAvgPacketsPerBulk,
		FwdAvgBulkRate:       fwdAvgBulkRate,
		BwdAvgBytesPerBulk:   bwdAvgBytesPerBulk,
		BwdAvgPacketsPerBulk: bwdAvgPacketsPerBulk,
		BwdAvgBulkRate:       bwdAvgBulkRate,
		ActiveMean:           flow.SliceMean(activePeriods),
		ActiveStd:            flow.SliceStd(activePeriods),
		ActiveMax:            flow.SliceMax(activePeriods),
		ActiveMin:            flow.SliceMin(activePeriods),
		IdleMean:             flow.SliceMean(idlePeriods),
		IdleStd:              flow.SliceStd(idlePeriods),
		IdleMax:              flow.SliceMax(idlePeriods),
		IdleMin:              flow.SliceMin(idlePeriods),
	}
}

// Predict sends flow features to the ML service and returns the prediction.
func (c *MLClient) Predict(features FlowFeatures) (*MLResponse, error) {
	if !c.available {
		return nil, fmt.Errorf("ML service unavailable")
	}

	jsonData, err := json.Marshal(features)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal features: %w", err)
	}

	resp, err := c.httpClient.Post(c.endpoint+"/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// Any transport-level failure (connection refused, timeout, DNS, etc.)
		// means the service is not usable right now — mark unavailable so
		// callers stop hammering it until the next successful HealthCheck.
		c.available = false
		return nil, fmt.Errorf("ML service request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ML service returned status %d", resp.StatusCode)
	}

	var mlResp MLResponse
	if err := json.NewDecoder(resp.Body).Decode(&mlResp); err != nil {
		return nil, fmt.Errorf("failed to decode ML response: %w", err)
	}

	return &mlResp, nil
}
