// 大きい保存blockのliteral分布に応じて、短い参照の費用と探索間隔を設定する。
package zstdencode

// configureMatchPolicy は全blockで方針を初期化し、保存の自動精度9・4byte探索候補だけ省探索を選ぶ。
// 推定3.5〜5bitのliteralが50〜96.875%残るsampleを、構造を含む狭いalphabetと扱う。
// 文字種が広い本文・単純な繰返し・HTTPと保存1/6は従来値を維持する。
func (e *Encoder) configureMatchPolicy(structured bool, size int) {
	e.referenceCost, e.repeatCost = 12*256, 7*256
	e.literalSkipMax, e.literalShift = 16, 4
	if e.archiveLog == 9 && e.optimizeEntropy && e.archiveMask == 0xffffffff && structured && size >= 16<<10 {
		e.referenceCost, e.repeatCost = 14*256, 14*256
		e.literalSkipMax, e.literalShift = 32, 3
	}
}
