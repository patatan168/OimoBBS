// 大きい回線表を単一コアでは逐次復号し、複数コアでは有界の行配列へ並列復号する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/identity"
	"oimobbs/internal/parallel"
	"oimobbs/internal/strictjson"
	"runtime"
)

type largeNetworkRowDecoder struct {
	serial bool
	count  int
	rows   []identity.NetworkClass
	bodies []json.RawMessage
}

// newLargeNetworkRowDecoder は単一コアでの保持量を抑え、出力用の行領域を先に確保する。
func newLargeNetworkRowDecoder(size int) *largeNetworkRowDecoder {
	d := &largeNetworkRowDecoder{serial: runtime.GOMAXPROCS(0) <= 1}
	capacity := min(networkRowLimit, size/128)
	if d.serial {
		d.rows = make([]identity.NetworkClass, 0, capacity)
	} else {
		d.bodies = make([]json.RawMessage, 0, capacity)
	}
	return d
}

// add は各行の上限検査後に呼ぶ。単一コアでは未復号本文をまとめて保持しない。
func (d *largeNetworkRowDecoder) add(body json.RawMessage) error {
	d.count++
	if d.serial {
		d.rows = append(d.rows, identity.NetworkClass{})
		return strictjson.Decode(body, &d.rows[len(d.rows)-1])
	}
	d.bodies = append(d.bodies, body)
	return nil
}

// finish は全workerを待ち、未知キー・破損・prefix重複を含む候補全体を拒否する。
// 未復号本文の合計は6MiB、行数は4万まで。workerは自分の行だけを書く。
func (d *largeNetworkRowDecoder) finish() ([]identity.NetworkClass, error) {
	if !d.serial {
		d.rows = make([]identity.NetworkClass, len(d.bodies))
		invalid := make([]bool, len(d.bodies))
		parallel.CPU(len(d.bodies), func(i int) { invalid[i] = strictjson.Decode(d.bodies[i], &d.rows[i]) != nil })
		for _, bad := range invalid {
			if bad {
				return nil, errNetworkData
			}
		}
	}
	if _, err := identity.CompileNetworks(d.rows, networkRowLimit); err != nil {
		return nil, errNetworkData
	}
	return d.rows, nil
}
