package definition

type BoolValue struct {
	*Metadata
	Value bool
}

func NewBoolValue(value bool, r Range, ref Reference) BoolValue {
	return BoolValue{
		Value: value,
		Metadata: &Metadata{
			Range:     r,
			Reference: ref,
		},
	}
}

func (b *BoolValue) IsTrue() bool {
	return b.Value
}

func (b *BoolValue) IsFalse() bool {
	return !b.Value
}
