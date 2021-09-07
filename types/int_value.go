package types

type IntValue interface {
	metadataProvider
	Value() int
	EqualTo(i int) bool
	LessThan(i int) bool
	GreaterThan(i int) bool
}

type intValue struct {
	metadata *Metadata
	value    int
}

func Int(value int, m *Metadata) IntValue {
	return &intValue{
		value:    value,
		metadata: m,
	}
}

func IntDefault(value int, m *Metadata) IntValue {
	b := Int(value, m)
	b.Metadata().isDefault = true
	return b
}

func IntExplicit(value int, m *Metadata) IntValue {
	b := Int(value, m)
	b.Metadata().isExplicit = true
	return b
}

func (b *intValue) Metadata() *Metadata {
	return b.metadata
}

func (b *intValue) Value() int {
	return b.value
}

func (b *intValue) EqualTo(i int) bool {
	return b.value == i
}

func (b *intValue) LessThan(i int) bool {
	return b.value < i
}

func (b *intValue) GreaterThan(i int) bool {
	return b.value > i
}
