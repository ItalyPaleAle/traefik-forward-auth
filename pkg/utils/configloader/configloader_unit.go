//go:build unit

// This file is only built when the "unit" tag is set

package configloader

// LoadFromMap exports the internal "loadFromMap" method
func LoadFromMap(dst any, m map[string]any) error {
	return loadFromMap(dst, m)
}
