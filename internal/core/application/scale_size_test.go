//go:build !race

package application

// scaleSize is how many delegations TestScale registers, and how many are due.
func scaleSize() (int, int) { return 800, 320 }
