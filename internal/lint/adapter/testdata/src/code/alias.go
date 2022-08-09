package code

import (
	x "provider"
	y "types"
)

func DoAnotherThing() x.Thing {
	thing := x.Thing{ // want "Provider struct provider.Thing is missing an initialised value for field 'Other'"
		Name: y.String{Value: "a name"},
	}
	return thing
}
