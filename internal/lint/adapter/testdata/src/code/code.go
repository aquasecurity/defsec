package code

import (
	"provider"
	"types"
)

func DoThing1() provider.Thing {
	thing := provider.Thing{ // want "Provider struct provider.Thing is missing an initialised value for field 'Other'"
		Name: types.String{Value: "a name"},
	}
	return thing
}

func DoThing2() provider.Thing {
	thing := provider.Thing{ // want "Provider struct provider.Thing is missing an initialised value for field 'Name'" "Provider struct provider.Thing is missing an initialised value for field 'Other'"
	}
	return thing
}

func DoThing3() provider.Thing {
	thing := provider.Thing{ // want "Provider struct provider.Thing is missing an initialised value for field 'Name'"
		Other: types.String{Value: "a name"},
	}
	return thing
}

func DoThing4() provider.Thing {
	thing := provider.Thing{
		Name:  types.String{Value: "a name"},
		Other: types.String{Value: "a name"},
	}
	return thing
}

func DoThing5() []provider.Thing {
	things := []provider.Thing{
		provider.Thing{ // want "Provider struct provider.Thing is missing an initialised value for field 'Other'"
			Name: types.String{Value: "a name"},
		},
	}
	return things
}

func DoThing6() provider.Thing {
	var thing provider.Thing // want "Provider struct provider.Thing should be explicitly initialised with all fields provided"
	thing.OK = true
	return thing
}

func DoThing7() (thing provider.Thing, err error) { // want "Provider struct provider.Thing should not be initialised via a named function return type"
	return thing, nil
}

func DoThing8() provider.Thing {
	return provider.Thing{ // want "Provider struct provider.Thing is missing an initialised value for field 'Other'"
		Name: types.String{Value: "a name"},
	}
}
