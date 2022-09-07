package armjson

func (p *parser) parseObject() (Node, error) {

	n := p.newNode(KindObject)
	c, err := p.next()
	if err != nil {
		return nil, err
	}

	if c != '{' {
		return nil, p.makeError("expecting object delimiter")
	}

	if err := p.parseWhitespace(); err != nil {
		return nil, err
	}

	// we've hit the end of the object
	if p.swallowIfEqual('}') {
		n.end = p.position
		return n, nil
	}

	var nextComments []Node

	/*
		{
			"a": "b", // whatever
			"c": "d"
		}


	*/

	// for each key/val
	for {

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		comments := make([]Node, len(nextComments))
		copy(comments, nextComments)
		nextComments = nil
		for {
			peeked, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if peeked != '/' {
				break
			}
			comment, err := p.parseComment()
			if err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}

		if comments != nil {
			if err := p.parseWhitespace(); err != nil {
				return nil, err
			}
		}

		key, err := p.parseString()
		if err != nil {
			return nil, err
		}

		if err := p.parseWhitespace(); err != nil {
			return nil, err
		}

		if !p.swallowIfEqual(':') {
			return nil, p.makeError("invalid character, expecting ':'")
		}

		val, err := p.parseElement()
		if err != nil {
			return nil, err
		}

		for {
			peeked, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if peeked != '/' {
				break
			}
			comment, err := p.parseComment()
			if err != nil {
				return nil, err
			}
			comments = append(comments, comment)
		}

		// we've hit the end of the object
		if p.swallowIfEqual('}') {
			key.(*node).comments = comments
			val.(*node).comments = comments
			n.content = append(n.content, key, val)
			n.end = p.position
			return n, nil
		}

		if !p.swallowIfEqual(',') {
			return nil, p.makeError("unexpected character - expecting , or }")
		}

		for {
			if err := p.parseWhitespace(); err != nil {
				return nil, err
			}
			peeked, err := p.peeker.Peek()
			if err != nil {
				return nil, err
			}
			if peeked != '/' {
				break
			}
			comment, err := p.parseComment()
			if err != nil {
				return nil, err
			}
			if comment.Range().Start.Line > val.Range().End.Line {
				nextComments = append(nextComments, comment)
			} else {
				comments = append(comments, comment)
			}
		}

		key.(*node).comments = comments
		val.(*node).comments = comments
		n.content = append(n.content, key, val)

	}

}
