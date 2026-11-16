// Package usage measures what a piece of work cost: wall time, CPU time (user
// plus system) and peak resident memory. Wall time alone misleads on a shared
// agent, where the same scan takes twice as long when another build runs
// beside it; CPU time and memory are what a scan asks of the machine.
package usage

import (
	"os"
	"time"
)

// Usage is the cost of one scanner run or one in-process step.
type Usage struct {
	Wall time.Duration
	CPU  time.Duration
	// MaxRSSKB is the peak resident memory, in KiB, of the largest process
	// involved (for a scanner: the largest process of its tree that was
	// waited for). Zero when the platform does not report it.
	MaxRSSKB int64
}

// OfProcess reads the cost of an exited child process. The kernel counts the
// child's own descendants that it waited for, so a launcher's engine
// processes are included.
func OfProcess(ps *os.ProcessState, wall time.Duration) Usage {
	if ps == nil {
		return Usage{Wall: wall}
	}
	return Usage{Wall: wall, CPU: ps.UserTime() + ps.SystemTime(), MaxRSSKB: maxRSSKB(ps)}
}

// Process is what this process and the children it waited for have cost
// since it started: CPU of both, and the peak resident memory of each.
type Process struct {
	CPU              time.Duration
	SelfMaxRSSKB     int64
	ChildrenMaxRSSKB int64
}

// SoFar reads the cost of this process so far.
func SoFar() Process {
	self, children := processCPU()
	selfRSS, childRSS := peaks()
	return Process{CPU: self + children, SelfMaxRSSKB: selfRSS, ChildrenMaxRSSKB: childRSS}
}

// Meter measures in-process work and the children it starts and waits for.
type Meter struct {
	start    time.Time
	self     time.Duration
	children time.Duration
}

// Start begins a measurement. Work running in other goroutines of this
// process at the same time is counted too; meter steps that run alone.
func Start() Meter {
	self, children := processCPU()
	return Meter{start: time.Now(), self: self, children: children}
}

// Stop ends the measurement. MaxRSSKB is the larger of this process's peak
// and the largest child's peak so far.
func (m Meter) Stop() Usage {
	self, children := processCPU()
	return Usage{
		Wall:     time.Since(m.start),
		CPU:      (self - m.self) + (children - m.children),
		MaxRSSKB: peakRSSKB(),
	}
}
