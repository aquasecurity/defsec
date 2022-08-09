package rapido

import (
	"runtime"
	"sync"

	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/state"
)

type ConcurrencyStrategy int

const (
	DefaultConcurrency ConcurrencyStrategy = iota
	CPUCountConcurrency
	OneAtATimeConcurrency
)

func ConcurrentAdapt[T any, S any](concurrencyStrategy ConcurrencyStrategy, items []T, logger debug.Logger, adapt func(T) (*S, error)) []S {
	return ConcurrentAdaptWithState(concurrencyStrategy, items, nil, logger, func(item T, _ *state.State) (*S, error) {
		return adapt(item)
	})
}

func ConcurrentAdaptWithState[T any, S any](concurrencyStrategy ConcurrencyStrategy, items []T, currentState *state.State, logger debug.Logger, adapt func(T, *state.State) (*S, error)) []S {

	processes := getProcessCount(concurrencyStrategy)
	logger.Log("Using %d processes to adapt %d resources", processes, len(items))

	mu := sync.Mutex{}

	var ch = make(chan T, 50)
	wg := sync.WaitGroup{}
	wg.Add(processes)

	var results []S

	for i := 0; i < processes; i++ {
		go func() {
			for {
				in, ok := <-ch
				if !ok {
					wg.Done()
					return
				}
				out, err := adapt(in, currentState)
				if err != nil {
					logger.Log("Error while adapting resource: %s", err)
					continue
				}

				if out != nil {
					mu.Lock()
					results = append(results, *out)
					mu.Unlock()
				}
			}
		}()
	}

	for _, item := range items {
		ch <- item
	}

	close(ch)
	wg.Wait()

	return results
}

func getProcessCount(strategy ConcurrencyStrategy) int {
	switch strategy {
	case OneAtATimeConcurrency:
		return 1
	case CPUCountConcurrency, DefaultConcurrency:
		return runtime.NumCPU()
	default:
		// this shouldn't be reached but at least we don't crash
		return 1
	}
}
