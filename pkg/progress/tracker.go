package progress

type Tracker interface {
	SetTotal(total int)
	Increment()
}

var NoProgress = nilTracker{}

type nilTracker struct{}

func (n nilTracker) SetTotal(total int) {}

func (n nilTracker) Increment() {}
