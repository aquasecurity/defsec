package definition

type Metadata struct {
	Range     Range
	Reference Reference
}

func NewMetadata(r Range, ref Reference) *Metadata {
	return &Metadata{
		Range:     r,
		Reference: ref,
	}
}

func (m *Metadata) WithReference(reference Reference) *Metadata {
	m.Reference = reference
	return m
}
