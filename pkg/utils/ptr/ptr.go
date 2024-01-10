package ptr

// Of returns a pointer of the value passed to it.
func Of[T any](val T) *T {
	return &val
}
