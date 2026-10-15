// 保存済みpackとdeltaから、年齢別の保守判断に必要な値だけを提供する。
package store

import (
	"oimobbs/internal/domain"
	"time"
)

// PackMaintenanceInfo は本文や主体情報を含まない所有ワーカー用の保存統計。
type PackMaintenanceInfo struct {
	Created, Expires, LastPacked domain.Time
	Generation                   uint64
	DeltaBytes, DeltaOperations  uint64
	Level                        uint8
	Codec                        uint8
}

// PackMaintenanceDecision は圧縮要否と固定の理由コード。expires以後は圧縮しない。
type PackMaintenanceDecision struct {
	Compact bool   `json:"compact"`
	Level   uint8  `json:"level"`
	Reason  string `json:"reason"`
}

// Decision は4MiB・1024操作・未整理deltaの24時間経過と年齢別levelを判定する。
// 無変更の同level packを毎日再生成せず、既存の強い圧縮levelも下げない。
func (s PackMaintenanceInfo) Decision(now domain.Time) PackMaintenanceDecision {
	d := PackMaintenanceDecision{Level: s.Level}
	if now >= s.Expires {
		d.Reason = "expired"
		return d
	}
	age := time.Unix(0, int64(now)).Sub(time.Unix(0, int64(s.Created)))
	target := uint8(1)
	if age >= 30*24*time.Hour {
		target = 9
	} else if age >= 7*24*time.Hour {
		target = 6
	}
	d.Level = max(target, s.Level)
	switch {
	case s.DeltaBytes >= 4<<20:
		d.Reason = "bytes"
	case s.DeltaOperations >= 1024:
		d.Reason = "operations"
	case s.DeltaOperations > 0 && time.Unix(0, int64(now)).Sub(time.Unix(0, int64(s.LastPacked))) >= 24*time.Hour:
		d.Reason = "elapsed"
	case s.Generation > 1 && target > s.Level:
		d.Reason = "level"
	}
	d.Compact = d.Reason != ""
	return d
}

// MaintenanceInfo は確定済み末尾だけを数える。未確定の部分書込みを整理対象にしない。
func (t *ThreadLog) MaintenanceInfo() PackMaintenanceInfo {
	info := PackMaintenanceInfo{Created: t.state.Created, Expires: t.state.Expires, LastPacked: t.state.Created, Generation: uint64(t.manifest.Generation), DeltaBytes: uint64(t.end - HeaderSize), DeltaOperations: uint64(t.state.Revision) - t.header.BaseSeq, Level: t.packLevel, Codec: t.packCodec}
	if t.base != nil {
		info.LastPacked = t.base.At
	}
	return info
}

// packMinimumLevel は本文・監査の混在levelで最も弱い値を返す。全pack検証後にだけ使う。
func packMinimumLevel(raw []byte) uint8 {
	_, sections, blocks, _ := parsePack(raw)
	level := uint8(9)
	for _, block := range blocks {
		level = min(level, block.chunk.Level)
	}
	audit := sections[3]
	pos := 32
	for i := uint32(0); i < le.Uint32(audit[24:]); i++ {
		level = min(level, audit[pos+13])
		pos += 24 + int(le.Uint32(audit[pos+8:]))
	}
	return level
}
