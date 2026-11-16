//go:build unix

package usage

import (
	"os"
	"runtime"
	"syscall"
	"time"
)

// rssKB converts ru_maxrss to KiB: Linux reports KiB, macOS bytes.
func rssKB(v int64) int64 {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return v / 1024
	}
	return v
}

func maxRSSKB(ps *os.ProcessState) int64 {
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok && ru != nil {
		return rssKB(int64(ru.Maxrss))
	}
	return 0
}

func cpuOf(ru *syscall.Rusage) time.Duration {
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func processCPU() (self, children time.Duration) {
	var s, c syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &s) == nil {
		self = cpuOf(&s)
	}
	if syscall.Getrusage(syscall.RUSAGE_CHILDREN, &c) == nil {
		children = cpuOf(&c)
	}
	return self, children
}

func peaks() (self, children int64) {
	var s, c syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &s)
	_ = syscall.Getrusage(syscall.RUSAGE_CHILDREN, &c)
	return rssKB(int64(s.Maxrss)), rssKB(int64(c.Maxrss))
}

func peakRSSKB() int64 {
	self, children := peaks()
	return max(self, children)
}
