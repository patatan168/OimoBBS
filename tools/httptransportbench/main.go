//go:build ignore

// 比較用toolは製品moduleの外部依存を増やさず、一時moduleで生成する。
// python3 scripts/quic-reference.py build-benchmark --output var/httptransportbench を使う。
package main

import "fmt"

func main() {
	fmt.Println("Build this reference-only tool with scripts/quic-reference.py build-benchmark")
}
