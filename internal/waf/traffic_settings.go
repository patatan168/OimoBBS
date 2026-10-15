// 大量アクセス制限の緩めの初期値と、管理入力の資源上限を定義する。
package waf

// TrafficSettings は公開側と管理側それぞれに適用する頻度・瞬間集中・実行数の上限。
type TrafficSettings struct {
	Enabled           bool `json:"enabled"`
	ClientRate        int  `json:"client_rate"`
	ClientBurst       int  `json:"client_burst"`
	GlobalRate        int  `json:"global_rate"`
	GlobalBurst       int  `json:"global_burst"`
	ClientConcurrent  int  `json:"client_concurrent"`
	GlobalConcurrent  int  `json:"global_concurrent"`
	SearchRate        int  `json:"search_rate"`
	SearchBurst       int  `json:"search_burst"`
	SearchGlobalRate  int  `json:"search_global_rate"`
	SearchGlobalBurst int  `json:"search_global_burst"`
	SearchConcurrent  int  `json:"search_concurrent"`
}

// DefaultTrafficSettings は共有回線や専ブラの巡回に余裕を持たせる初期値を返す。
func DefaultTrafficSettings() TrafficSettings {
	return TrafficSettings{
		Enabled: true, ClientRate: 60, ClientBurst: 180, GlobalRate: 300, GlobalBurst: 600,
		ClientConcurrent: 32, GlobalConcurrent: 128,
		SearchRate: 2, SearchBurst: 10, SearchGlobalRate: 12, SearchGlobalBurst: 24, SearchConcurrent: 4,
	}
}

// Valid はゼロ・過大値と、全体より大きい利用者枠などの不整合を拒否する。
func (s TrafficSettings) Valid() bool {
	return s.ClientRate >= 1 && s.ClientRate <= 10000 && s.ClientBurst >= s.ClientRate && s.ClientBurst <= 100000 &&
		s.GlobalRate >= s.ClientRate && s.GlobalRate <= 100000 && s.GlobalBurst >= s.GlobalRate && s.GlobalBurst >= s.ClientBurst && s.GlobalBurst <= 200000 &&
		s.ClientConcurrent >= 1 && s.ClientConcurrent <= 128 && s.GlobalConcurrent >= s.ClientConcurrent && s.GlobalConcurrent <= 2048 &&
		s.SearchRate >= 1 && s.SearchRate <= s.ClientRate && s.SearchBurst >= s.SearchRate && s.SearchBurst <= s.ClientBurst &&
		s.SearchGlobalRate >= s.SearchRate && s.SearchGlobalRate <= s.GlobalRate && s.SearchGlobalBurst >= s.SearchGlobalRate && s.SearchGlobalBurst >= s.SearchBurst && s.SearchGlobalBurst <= s.GlobalBurst &&
		s.SearchConcurrent >= 1 && s.SearchConcurrent <= s.GlobalConcurrent
}
