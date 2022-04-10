package parser

type Option func(p *Parser)

func OptionWithSkipRequired(skipRequired bool) Option {
	return func(p *Parser) {
		p.skipRequired = skipRequired
	}
}
