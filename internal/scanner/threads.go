package scanner

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// defaultScanThreads is where more cores stop helping the code scanner. On a
// 14-thread machine it took as long or longer with all of them than with 4
// (five repositories, 30 s to 160 s scans) and used up to twice the CPU.
const defaultScanThreads = 4

// scanThreads is the number of cores the code scanner uses in one scan:
// SDT_SCAN_THREADS when set, else every core up to defaultScanThreads.
func scanThreads() int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SDT_SCAN_THREADS"))); err == nil && n >= 1 {
		return n
	}
	return min(runtime.NumCPU(), defaultScanThreads)
}
