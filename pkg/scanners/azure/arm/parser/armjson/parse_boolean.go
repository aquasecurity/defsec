package armjson

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/types"
)

var trueRunes = []rune("true")
var falseRunes = []rune("false")

func (p *parser) parseBoolean(parentMetadata *types.Metadata) (Node, error) {

	n, _ := p.newNode(KindBoolean, parentMetadata)

	r, err := p.peeker.Peek()
	if err != nil {
		return nil, err
	}

	if r == 't' {
		for _, expected := range trueRunes {
			if !p.swallowIfEqual(expected) {
				return nil, fmt.Errorf("unexpected character in boolean value")
			}
		}
		n.raw = true
		n.end = p.position
		return n, err
	}

	for _, expected := range falseRunes {
		if !p.swallowIfEqual(expected) {
			return nil, fmt.Errorf("unexpected character in boolean value")
		}
	}
	n.raw = false
	n.end = p.position
	return n, nil
}
