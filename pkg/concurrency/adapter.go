package concurrency

import (
	"sync"

	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/state"
)

type Context interface {
	Logger() debug.Logger
	ConcurrencyStrategy() Strategy
}

func Adapt[T any, S any](items []T, adapter Context, adapt func(T) (*S, error)) []S {
	return AdaptWithStrategy(items, nil, adapter, func(item T, _ *state.State) (*S, error) {
		return adapt(item)
	})
}

func AdaptWithStrategy[T any, S any](items []T, currentState *state.State, adapter Context, adapt func(T, *state.State) (*S, error)) []S {
	processes := getProcessCount(adapter.ConcurrencyStrategy())
	logger := adapter.Logger()
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
