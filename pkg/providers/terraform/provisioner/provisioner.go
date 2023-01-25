package provisioner

type Provisioner struct {
	Files       []File
	LocalExecs  []LocalExec
	RemoteExecs []RemoteExec
}
