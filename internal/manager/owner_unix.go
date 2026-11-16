package manager

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func sameOwner(st fs.FileInfo) error {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return errors.New("not owner")
	}
	return nil
}
