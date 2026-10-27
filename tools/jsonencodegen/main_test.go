// 型定義の更新時に、生成コードの再生成漏れを製品検査で検出する。
package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestGeneratedFilesCurrent(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range configuredTargets() {
		cfg.path = filepath.Join(root, cfg.path)
		g := generator{target: cfg, check: true, seen: map[reflect.Type]bool{}, imports: map[string]bool{}}
		g.generate()
	}
}
