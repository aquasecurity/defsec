package armjson

func (p *parser) parseComment() (Node, error) {

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}

	_, err := p.next()
	if err != nil {
		return nil, err
	}

	b, err := p.next()
	if err != nil {
		return nil, err
	}

	switch b {
	case '/':
		return p.parseLineComment()
	case '*':
		return p.parseBlockComment()
	default:
		return nil, p.makeError("expecting comment delimiter")
	}
}

func (p *parser) parseLineComment() (Node, error) {

	n := p.newNode(KindComment)

	var comment string
	for {
		c, err := p.next()
		if err != nil {
			return nil, err
		}
		if c == '\n' {
			p.position.Column = 1
			p.position.Line++
			break
		}
		comment += string(c)
	}

	n.raw = comment

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}
	return n, nil
}

func (p *parser) parseBlockComment() (Node, error) {

	n := p.newNode(KindComment)

	var comment string

	for {
		c, err := p.next()
		if err != nil {
			return nil, err
		}
		if c == '*' {
			c, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if c == '/' {
				break
			}
			comment += "*"
		} else {
			if c == '\n' {
				p.position.Column = 1
				p.position.Line++
			}
			comment += string(c)
		}
	}

	n.raw = comment

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}

	return n, nil
}
