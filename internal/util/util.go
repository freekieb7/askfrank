package util

type Optional[T any] struct {
	Value T
	Some  bool
}
