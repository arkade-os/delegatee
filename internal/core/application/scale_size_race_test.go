//go:build race

package application

// the race detector makes the curve math ~15x slower
func scaleSize() (int, int) { return 300, 120 }
