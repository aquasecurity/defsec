package concurrency

import "runtime"

type Strategy int

const (
	DefaultStrategy Strategy = iota
	CPUCountStrategy
	OneAtATimeStrategy
)

func getProcessCount(strategy Strategy) int {
	switch strategy {
	case OneAtATimeStrategy:
		return 1
	case CPUCountStrategy, DefaultStrategy:
		return runtime.NumCPU()
	default:
		// this shouldn't be reached but at least we don't crash
		return 1
	}
}
