package config

// DefaultActionOr returns the default action or fallback.
func (p Policy) DefaultActionOr(fallback string) string {
	if p.DefaultAction == "" {
		return fallback
	}
	return p.DefaultAction
}
