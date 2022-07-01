package progress

type Tracker interface {
	SetTotalServices(i int)
	StartService(name string)
	FinishService()
	ServiceTracker
}

type ServiceTracker interface {
	SetServiceLabel(label string)
	SetTotalResources(i int)
	IncrementResource()
}

var NoProgress = nilTracker{}

type nilTracker struct{}

func (n nilTracker) SetTotalServices(_ int)   {}
func (n nilTracker) SetTotalResources(_ int)  {}
func (n nilTracker) IncrementResource()       {}
func (n nilTracker) StartService(_ string)    {}
func (n nilTracker) FinishService()           {}
func (n nilTracker) SetServiceLabel(_ string) {}
