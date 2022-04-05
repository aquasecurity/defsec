package resolvers

import (
	"os"
)

func isWritable(path string) bool {
	isWritable = false
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	err = nil
	if !info.IsDir() {
		return false
	}

	// Check if the user bit is enabled in file permission
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return false
	}

	return true
}
