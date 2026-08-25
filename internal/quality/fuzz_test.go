package quality

import "testing"

// FuzzDecodeConfig is the boundary-fuzz lane for the configuration seam: the
// decoder must never panic and must fail closed on any malformed input.
func FuzzDecodeConfig(f *testing.F) {
	f.Add([]byte(validConfigJSON()))
	f.Add([]byte(`{"schemaVersion":4,"toolchain":{"language":"go","version":"1.26.6"},"extends":["opentofu@1"],"gates":[{"name":"a","command":"go"}]}`))
	f.Add([]byte(`{"schemaVersion":3,"toolchain":{"goVersion":"1.26.6"},"gates":[{"name":"a","command":"go"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeConfig(data)
	})
}

// FuzzDecodePackDescriptor is the boundary-fuzz lane for the capability pack
// descriptor decoder: the decoder must never panic and must fail closed on
// any malformed input.
func FuzzDecodePackDescriptor(f *testing.F) {
	f.Add([]byte(validPackJSON()))
	f.Add([]byte(`{"schema":"capability-pack/v2"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodePackDescriptor(data)
	})
}
