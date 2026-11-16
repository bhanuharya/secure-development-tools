//go:build !unix

package usage

import (
	"os"
	"time"
)

func maxRSSKB(*os.ProcessState) int64 { return 0 }

func processCPU() (time.Duration, time.Duration) { return 0, 0 }

func peaks() (int64, int64) { return 0, 0 }
