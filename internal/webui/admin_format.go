// 管理画面で容量と帯域を、桁を追わずに読める単位付き表示へ変換する。
package webui

import "fmt"

// formatBytes は非負の容量をIEC単位で表示する。正確なバイト数は詳細表示に残す。
func formatBytes(value uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	n, unit := float64(value), 0
	for n >= 1024 && unit < len(units)-1 {
		n /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d B", value)
	}
	return fmt.Sprintf("%.1f %s", n, units[unit])
}

// formatMbps は運用設定と同じ10進のMbpsで送信予算を表示する。
func formatMbps(value uint64) string { return fmt.Sprintf("%.1f Mbps", float64(value)/1_000_000) }
