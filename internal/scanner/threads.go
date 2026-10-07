package scanner

import (
	"os"
	"strconv"
	"strings"
)

// scanThreads is the number of cores the code scanner may use in one scan
// (SDT_SCAN_THREADS), or 0 for the scanner's own default: every core.
func scanThreads() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SDT_SCAN_THREADS")))
	if err != nil || n < 1 {
		return 0
	}
	return n
}
