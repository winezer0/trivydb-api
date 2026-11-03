//go:build !windows

package trivydbapi

import "os"

func replaceFile(source, target string) error { return os.Rename(source, target) }
