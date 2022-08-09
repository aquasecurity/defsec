package rapido

import (
	"runtime"
	"sync"

	"github.com/aquasecurity/defsec/pkg/debug"
)

func ConcurrentAdapt[T any, S any](adapt func(T) *S, items []T, logger debug.Logger) []S {
	processes := runtime.NumCPU() - 1
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
				if out := adapt(in); out != nil {
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
