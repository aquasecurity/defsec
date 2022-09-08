package types

import (
	"fmt"
	"strings"
)

type metadataProvider interface {
	GetMetadata() Metadata
	GetRawValue() interface{}
}

type Metadata struct {
	rnge           Range
	ref            Reference
	isManaged      bool
	isDefault      bool
	isExplicit     bool
	isUnresolvable bool
	parent         *Metadata
	internal       interface{} // used for different storage depending on consumer
}

func (m *Metadata) SetInternal(internal interface{}) {
	m.internal = internal
}

func (m *Metadata) Internal() interface{} {
	return m.internal
}

func (m *Metadata) ToRego() interface{} {
	if m.rnge == nil {
		return map[string]interface{}{
			"managed":  m.isManaged,
			"explicit": m.isExplicit,
		}
	}
	refStr := ""
	if ref := m.Reference(); ref != nil {
		refStr = ref.String()
	}
	return map[string]interface{}{
		"filepath":  m.Range().GetFilename(),
		"startline": m.Range().GetStartLine(),
		"endline":   m.Range().GetEndLine(),
		"managed":   m.isManaged,
		"explicit":  m.isExplicit,
		"fskey":     CreateFSKey(m.Range().GetFS()),
		"resource":  refStr,
	}
}

func NewMetadata(r Range, ref Reference) Metadata {
	if r == nil {
		panic("range is nil")
	}
	if ref == nil {
		panic("reference is nil")
	}
	return Metadata{
		rnge:      r,
		ref:       ref,
		isManaged: true,
	}
}

func NewUnresolvableMetadata(r Range, ref Reference) Metadata {
	unres := NewMetadata(r, ref)
	unres.isUnresolvable = true
	return unres
}

func NewExplicitMetadata(r Range, ref Reference) Metadata {
	m := NewMetadata(r, ref)
	m.isExplicit = true
	return m
}

func (m Metadata) WithParentPtr(p *Metadata) Metadata {
	if base, ok := m.rnge.(baseRange); ok {
		if p.rnge.GetFS() != nil {
			if base.fs == nil {
				base.fs = p.rnge.GetFS()
			}
		}
		if p.rnge.GetFilename() != "" {
			if base.filename == "" {
				base.filename = p.rnge.GetFilename()
			}
		}
		if p.rnge.GetFSKey() != "" {
			if base.fsKey == "" {
				base.fsKey = p.rnge.GetFSKey()
			}
		}
		m.rnge = base
	}
	m.parent = p
	return m
}

func (m Metadata) WithParent(p Metadata) Metadata {
	m.WithParentPtr(&p)
	return m
}

func (m Metadata) Parent() *Metadata {
	return m.parent
}

func (m Metadata) Root() Metadata {
	meta := &m
	for meta.Parent() != nil {
		meta = meta.Parent()
	}
	return *meta
}

func (m Metadata) IsMultiLine() bool {
	return m.rnge.GetStartLine() < m.rnge.GetEndLine()
}

func NewUnmanagedMetadata() Metadata {
	m := NewMetadata(NewRange("", 0, 0, "", nil), &FakeReference{})
	m.isManaged = false
	return m
}

func NewTestMetadata() Metadata {
	return NewMetadata(NewRange("test.test", 123, 123, "", nil), &FakeReference{})
}

func NewApiMetadata(provider string, parts ...string) Metadata {
	return NewMetadata(NewRange(fmt.Sprintf("/%s/%s", provider, strings.Join(parts, "/")), 0, 0, "", nil), &FakeReference{})
}

func NewRemoteMetadata(id string) Metadata {
	return NewMetadata(NewRange(id, 0, 0, "remote", nil), NewNamedReference(id))
}

func (m Metadata) IsDefault() bool {
	return m.isDefault
}

func (m Metadata) IsResolvable() bool {
	return !m.isUnresolvable
}

func (m Metadata) IsExplicit() bool {
	return m.isExplicit
}

func (m Metadata) String() string {
	return m.ref.String()
}

func (m Metadata) Reference() Reference {
	return m.ref
}

func (m Metadata) Range() Range {
	if m.rnge == nil {
		return NewRange("unknown", 0, 0, "", nil)
	}
	return m.rnge
}

func (m *Metadata) SetRange(r Range) {
	m.rnge = r
}

func (m *Metadata) SetReference(r Reference) {
	m.ref = r
}

func (m Metadata) IsManaged() bool {
	return m.isManaged
}

func (m Metadata) IsUnmanaged() bool {
	return !m.isManaged
}

type BaseAttribute struct {
	metadata Metadata
}

func (b BaseAttribute) GetMetadata() Metadata {
	return b.metadata
}

func (m Metadata) GetMetadata() Metadata {
	return m
}

func (m Metadata) GetRawValue() interface{} {
	return nil
}
