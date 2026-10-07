package scanner

import "time"

// taskTimeout is a scanner's time limit in seconds: the duration set for it in the scan
// configuration (scanners.<name>.timeout, validated on load), else the adapter's default.
func taskTimeout(configured string, fallback int) int {
	if d, err := time.ParseDuration(configured); err == nil && d >= time.Second {
		return int(d / time.Second)
	}
	return fallback
}
