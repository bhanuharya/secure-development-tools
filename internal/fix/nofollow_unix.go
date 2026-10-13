//go:build unix

package fix

import "syscall"

// openNoFollow makes an open fail when the last element of the path is a
// symbolic link.
const openNoFollow = syscall.O_NOFOLLOW
