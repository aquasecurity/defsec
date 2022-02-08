package scanner

// Option ...
type Option func(s *Scanner)

// OptionIncludePassed ...
func OptionIncludePassed() func(s *Scanner) {
	return func(s *Scanner) {
		s.includePassed = true
	}
}

// OptionIncludeIgnored ...
func OptionIncludeIgnored() func(s *Scanner) {
	return func(s *Scanner) {
		s.includeIgnored = true
	}
}
