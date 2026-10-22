// 署名journalのpayloadを一つの表現で保持し、照会時に完全なEntryへ復元する。
package evidence

import "encoding/base64"

// retainJournalEntry は検証済み元byteを変更せず、重複表現だけを解放可能にする。
// WALの署名valueと保持量の容量計算は変更しない。payloadの所有権は呼出元が確保する。
func retainJournalEntry(event Event, payload []byte) Entry {
	if optionalKind(event.Kind) {
		event.Payload = ""
	} else if requiredKind(event.Kind) {
		// 必須proposalは投稿所有者も同じ不変base64を参照するため、raw側を省く。
		payload = nil
	}
	return Entry{event, payload}
}

// completeJournalEntry は検証済みの片方の表現から復元する。JSONの再符号化や再署名はしない。
func completeJournalEntry(entry Entry) Entry {
	if entry.Event.Payload == "" && optionalKind(entry.Event.Kind) {
		entry.Event.Payload = base64.StdEncoding.EncodeToString(entry.Payload)
	}
	if entry.Payload == nil && requiredKind(entry.Event.Kind) {
		// 保存時・replay時に正規base64と署名を照合済みであり、以後この値は変更しない。
		entry.Payload, _ = base64.StdEncoding.DecodeString(entry.Event.Payload)
	}
	return entry
}
