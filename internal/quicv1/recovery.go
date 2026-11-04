// RFC9002のRTT推定・packet/time閾値損失検出・NewReno・PTOを接続actorから操作する。
package quicv1

import (
	"time"
)

const datagramSize = 1200

type sentPacket struct {
	number          uint64
	at              time.Time
	size            int
	frames          []byte
	retransmittable bool
	mtuProbe        int
	refs            []*sendBlock
}
type numberSpace struct {
	next, largestReceived uint64
	received              bool
	receiveSlots          [4096]uint64
	ranges                []packetSpan
	largestReceivedAt     time.Time
	read, write           *packetKeys
	sent                  map[uint64]sentPacket
	sentOrder             []uint64
	sentHead              int
	cryptoRX              reassembly
	cryptoTX              uint64
	ackPending            bool
	ackCount              int
	ackAt                 time.Time
	largestAcked          uint64
	hasAcked              bool
}

func newNumberSpace() numberSpace {
	return numberSpace{sent: make(map[uint64]sentPacket), cryptoRX: reassembly{limit: 64 << 10}}
}

type packetSpan struct{ low, high uint64 }

// receive は固定ringで重複を検出し、ACK区間を最大16個にまとめる。
// 要求ごとの全履歴sortを避け、packet番号が飛んでも4096個の履歴に収める。
func (s *numberSpace) receive(pn uint64, now time.Time) bool {
	if s.received && s.largestReceived > pn && s.largestReceived-pn >= 4096 {
		return false
	}
	slot := pn % 4096
	if s.receiveSlots[slot] == pn+1 {
		return false
	}
	s.receiveSlots[slot] = pn + 1
	if !s.received || pn > s.largestReceived {
		s.largestReceived = pn
		s.largestReceivedAt = now
		s.received = true
	}
	floor := uint64(0)
	if s.largestReceived >= 4096 {
		floor = s.largestReceived - 4095
	}
	var scratch [17]packetSpan
	ranges := scratch[:0]
	added := false
	for _, span := range s.ranges {
		if !added && pn > span.high {
			ranges = append(ranges, packetSpan{pn, pn})
			added = true
		}
		if pn >= span.low && pn <= span.high {
			added = true
		}
		ranges = append(ranges, span)
	}
	if !added {
		ranges = append(ranges, packetSpan{pn, pn})
	}
	s.ranges = s.ranges[:0]
	for _, span := range ranges {
		if span.high < floor {
			break
		}
		span.low = max(span.low, floor)
		if len(s.ranges) > 0 {
			last := &s.ranges[len(s.ranges)-1]
			if span.high+1 >= last.low {
				last.low = min(last.low, span.low)
				continue
			}
		}
		if len(s.ranges) == 16 {
			break
		}
		s.ranges = append(s.ranges, span)
	}
	return true
}

// ackFrame は降順の受信区間を直接符号化する。ACKサイズは最大16区間に制限する。
func (s *numberSpace) ackFrame(now time.Time) []byte {
	if !s.ackPending || len(s.ranges) == 0 {
		return nil
	}
	ranges := s.ranges
	delay := max(time.Duration(0), now.Sub(s.largestReceivedAt))
	out := appendVarint(make([]byte, 0, 32), 2)
	out = appendVarint(out, s.largestReceived)
	out = appendVarint(out, uint64(delay.Microseconds())>>3)
	out = appendVarint(out, uint64(len(ranges)-1))
	out = appendVarint(out, ranges[0].high-ranges[0].low)
	for i := 1; i < len(ranges); i++ {
		out = appendVarint(out, ranges[i-1].low-ranges[i].high-2)
		out = appendVarint(out, ranges[i].high-ranges[i].low)
	}
	s.ackPending = false
	s.ackCount = 0
	return out
}

type recovery struct {
	latest, smoothed, variance, minRTT time.Duration
	cwnd, ssthresh, inFlight           int
	recoveryStart                      time.Time
	ptoCount                           uint
	lastSent                           time.Time
	peerMaxAckDelay                    time.Duration
	peerAckExponent                    uint64
}

func newRecovery() recovery {
	return recovery{smoothed: 333 * time.Millisecond, variance: 333 * time.Millisecond / 2, cwnd: 10 * datagramSize, ssthresh: 1 << 30, peerMaxAckDelay: 25 * time.Millisecond, peerAckExponent: 3}
}
func (r *recovery) updateRTT(sample, delay time.Duration, application bool) {
	r.latest = sample
	if r.minRTT == 0 {
		r.minRTT = sample
		r.smoothed = sample
		r.variance = sample / 2
		return
	}
	r.minRTT = min(r.minRTT, sample)
	if application {
		delay = min(delay, r.peerMaxAckDelay)
		if sample >= r.minRTT+delay {
			sample -= delay
		}
	}
	diff := r.smoothed - sample
	if diff < 0 {
		diff = -diff
	}
	r.variance = (3*r.variance + diff) / 4
	r.smoothed = (7*r.smoothed + sample) / 8
}
func (r *recovery) pto() time.Duration {
	value := r.basePTO()
	shift := min(r.ptoCount, uint(6))
	return value * time.Duration(1<<shift)
}
func (r *recovery) acknowledged(p sentPacket) {
	r.inFlight = max(0, r.inFlight-p.size)
	if !p.at.After(r.recoveryStart) {
		return
	}
	if r.cwnd < r.ssthresh {
		r.cwnd += p.size
	} else {
		r.cwnd += max(1, datagramSize*p.size/r.cwnd)
	}
}
func (r *recovery) lost(p sentPacket, now time.Time) {
	r.inFlight = max(0, r.inFlight-p.size)
	if !p.at.After(r.recoveryStart) {
		return
	}
	r.recoveryStart = now
	r.cwnd = max(2*datagramSize, r.cwnd/2)
	r.ssthresh = r.cwnd
}

// basePTO はidle期限が再送backoffに引きずられて延びないよう、通常時のPTOを返す。
func (r *recovery) basePTO() time.Duration {
	return r.smoothed + max(4*r.variance, time.Millisecond) + r.peerMaxAckDelay
}

// pruneSent はACK/損失で解放済みの先頭を進め、送信順の履歴も固定上限内へ回収する。
func (s *numberSpace) pruneSent() {
	for s.sentHead < len(s.sentOrder) {
		if _, ok := s.sent[s.sentOrder[s.sentHead]]; ok {
			break
		}
		s.sentHead++
	}
	if s.sentHead == len(s.sentOrder) {
		s.sentOrder = s.sentOrder[:0]
		s.sentHead = 0
		return
	}
	if s.sentHead >= 256 && s.sentHead*2 >= len(s.sentOrder) {
		copy(s.sentOrder, s.sentOrder[s.sentHead:])
		s.sentOrder = s.sentOrder[:len(s.sentOrder)-s.sentHead]
		s.sentHead = 0
	}
	if len(s.sentOrder) >= 2048 {
		kept := s.sentOrder[:0]
		for _, pn := range s.sentOrder[s.sentHead:] {
			if _, ok := s.sent[pn]; ok {
				kept = append(kept, pn)
			}
		}
		s.sentOrder = kept
		s.sentHead = 0
	}
}
