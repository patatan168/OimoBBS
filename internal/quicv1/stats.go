// 読取り専用の集計値を、接続actorの状態を直接共有せずに取得する。
package quicv1

// Stats は性能検証用の接続数とMTU状態。アドレス・要求内容・鍵を含めない。
type Stats struct {
	Connections    int    `json:"connections"`
	MTU1200        int    `json:"mtu_1200"`
	MTU1350        int    `json:"mtu_1350"`
	MTU1452        int    `json:"mtu_1452"`
	Fallbacks      uint64 `json:"mtu_fallbacks"`
	GSODisabled    bool   `json:"gso_disabled"`
	SentPackets    uint64 `json:"sent_packets"`
	LostPackets    uint64 `json:"lost_packets"`
	SendCalls      uint64 `json:"send_calls"`
	PreparedWrites uint64 `json:"prepared_writes"`
	WindowMax      int64  `json:"congestion_window_max"`
	RTTMax         int64  `json:"smoothed_rtt_us_max"`
}

// Stats は固定上限の接続mapとatomic値だけを読み、I/Oを発生させない。
func (l *Listener) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := Stats{Connections: len(l.connections), Fallbacks: l.mtuFallbacks.Load(), GSODisabled: l.gsoDisabled.Load()}
	s.SentPackets = l.sentPackets.Load()
	s.LostPackets = l.lostPackets.Load()
	s.SendCalls = l.sendCalls.Load()
	s.PreparedWrites = l.preparedWrites.Load()
	for _, c := range l.connections {
		s.WindowMax = max(s.WindowMax, c.statsWindow.Load())
		s.RTTMax = max(s.RTTMax, c.statsRTT.Load()/1000)
		mtu := int(c.mtuSnapshot.Load())
		switch {
		case mtu >= 1452:
			s.MTU1452++
		case mtu >= 1350:
			s.MTU1350++
		default:
			s.MTU1200++
		}
	}
	return s
}
