//go:build race

package application

// the race detector makes the curve math ~15x slower: keep the test short
// (still 3 indexer chunks and 8 intents)
func scaleSize() (int, int) { return 300, 120 }
