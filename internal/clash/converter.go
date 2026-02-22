// Package clash provides conversion from Clash YAML configurations to K2RULEV2 binary format.
package clash

// NewSliceConverter creates a new SliceConverter.
// Placeholder to make tests compile.
func NewSliceConverter() *SliceConverter {
	return &SliceConverter{}
}

// SliceConverter converts Clash YAML config to K2RULEV2 binary format.
type SliceConverter struct{}

// SetProviderRules sets provider rules directly.
func (c *SliceConverter) SetProviderRules(name string, rules []string) {}

// LoadProvider loads provider rules from content (YAML payload or plain text).
func (c *SliceConverter) LoadProvider(name, content string) error { return nil }

// Convert converts Clash YAML config to K2RULEV2 binary.
func (c *SliceConverter) Convert(yamlContent string) ([]byte, error) { return nil, nil }
