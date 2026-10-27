// LinuxのプロセスCPU時間を使い、並列圧縮の経過時間と総計算量を区別する。
package testutil

import (
	"syscall"
	"time"
)

// ProcessCPUTime は全threadのuserとsystem CPU時間の合計を返す。待機時間は含まない。
func ProcessCPUTime() (time.Duration, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second + time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond, nil
}
