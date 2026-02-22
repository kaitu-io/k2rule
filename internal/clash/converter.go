package clash

type SliceConverter struct{}

func NewSliceConverter() *SliceConverter { return &SliceConverter{} }
func (c *SliceConverter) SetProviderRules(name string, rules []string) {}
func (c *SliceConverter) LoadProvider(name, content string) error { return nil }
func (c *SliceConverter) Convert(yaml string) ([]byte, error) { return nil, nil }
