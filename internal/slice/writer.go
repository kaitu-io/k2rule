package slice

type SliceWriter struct{}

func NewSliceWriter(fallback uint8) *SliceWriter { return &SliceWriter{} }
func (w *SliceWriter) AddDomainSlice(domains []string, target uint8) error { return nil }
func (w *SliceWriter) Build() ([]byte, error) { return nil, nil }
