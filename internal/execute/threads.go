package execute

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// defaultScanThreads is where more cores stop paying for themselves. The engine
// runs its workers as threads of one process, and each one past the first adds
// more CPU than it saves time: on four services (6 s to 60 s code scans), 2
// workers took 24% less time than 1 for 22% more CPU, while 4 took another 11%
// less time for 37% more CPU than 2. Beyond 4 it took as long or longer.
const defaultScanThreads = 2

// ScanThreads is the number of cores a code-scanning engine uses in one scan
// (the rule scan and the endpoint fact run alike):
// SDT_SCAN_THREADS when set, else every core up to defaultScanThreads.
func ScanThreads() int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SDT_SCAN_THREADS"))); err == nil && n >= 1 {
		return n
	}
	return min(runtime.NumCPU(), defaultScanThreads)
}
