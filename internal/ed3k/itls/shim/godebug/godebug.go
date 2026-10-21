// Package godebug stands in for internal/godebug. This fork reads no GODEBUG
// settings: every setting has its default value, which is what the standard
// library uses when GODEBUG does not name it.
package godebug

// Setting is one named GODEBUG setting.
type Setting struct{ name string }

// New returns the setting name.
func New(name string) *Setting { return &Setting{name: name} }

// Name returns the setting's name.
func (s *Setting) Name() string { return s.name }

// Value returns "", the default.
func (s *Setting) Value() string { return "" }

// IncNonDefault counts nothing.
func (s *Setting) IncNonDefault() {}
