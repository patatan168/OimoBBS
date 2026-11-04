// 公開配信headerの符号化結果だけを接続内で再利用し、秘密情報と無制限な履歴を残さない。
package http3native

// appendLiteral は動的tableを使わないpeerにも同じwire表現を再利用する。
// 認証headerや任意headerは保存せず、キーと符号列を合わせ8KiB・64件に制限する。
// q.muを保持して呼び、返却先へは必ずコピーする。
func (q *QPACK) appendLiteral(dst []byte, f Field) []byte {
	if !dynamicAllowed(f.Name) || len(f.Value) > 512 {
		return literal(dst, f)
	}
	return append(dst, q.literalBytesFor(f)...)
}

// literalBytesFor の返却値は読取り専用。共有する符号列は呼出元へ直接公開しない。
func (q *QPACK) literalBytesFor(f Field) []byte {
	if !dynamicAllowed(f.Name) || len(f.Value) > 512 {
		return literal(nil, f)
	}
	if encoded, ok := q.literals[f]; ok {
		return encoded
	}
	encoded := literal(nil, f)
	size := len(f.Name) + len(f.Value) + len(encoded)
	if len(q.literals) >= 64 || q.literalBytes+size > 8<<10 {
		clear(q.literals)
		q.literalBytes = 0
	}
	if q.literals == nil {
		q.literals = make(map[Field][]byte)
	}
	q.literals[f] = encoded
	q.literalBytes += size
	return encoded
}

// dynamicWorthwhile はSection ACKが独立packetになる場合の暗号化・stream header分も考慮する。
// 動的参照で64byte以上減るsectionだけを対象にし、小さい304で確認通信の方が増えるのを避ける。
func (q *QPACK) dynamicWorthwhile(fields []Field) bool {
	saving := 0
	for _, f := range fields {
		if _, static := staticIndex(f); !static && dynamicAllowed(f.Name) {
			saving += len(q.literalBytesFor(f)) - 3
			if saving >= 64 {
				return true
			}
		}
	}
	return false
}

// readValue は公開fieldのHuffman展開だけを再利用する。業務処理・認可は全要求で実行する。
// never-index指定と秘密情報は保存せず、入力256byte・展開512byte・合計4KiB・32件に制限する。
func (q *QPACK) readValue(first byte, r *fieldReader, name string, indexable bool) (string, error) {
	data, err := stringData(first, 7, r)
	if err != nil {
		return "", err
	}
	if first&0x80 == 0 {
		return string(data), nil
	}
	cache := indexable && publicRequestValue(name) && len(data) <= 256
	if cache {
		if value, ok := q.values[string(data)]; ok {
			return value, nil
		}
	}
	value, err := decodeHuffman(data)
	if err != nil || !cache || len(value) > 512 {
		return value, err
	}
	size := len(data) + len(value)
	if len(q.values) >= 32 || q.valueBytes+size > 4096 {
		clear(q.values)
		q.valueBytes = 0
	}
	if q.values == nil {
		q.values = make(map[string]string)
	}
	q.values[string(data)] = value
	q.valueBytes += size
	return value, nil
}

func publicRequestValue(name string) bool {
	switch name {
	case ":method", ":scheme", ":authority", "accept", "accept-encoding", "accept-language", "range", "if-range", "if-none-match", "user-agent", "content-type":
		return true
	}
	return false
}
