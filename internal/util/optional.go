package util

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type Optional[T any] struct {
	Val   T
	IsSet bool
}

func Some[T any](v T) Optional[T] {
	return Optional[T]{Val: v, IsSet: true}
}

func None[T any]() Optional[T] {
	return Optional[T]{}
}

func (o Optional[T]) Unwrap() T {
	if !o.IsSet {
		panic("called Unwrap on a None value")
	}
	return o.Val
}

func (o Optional[T]) UnwrapOr(defaultVal T) T {
	if !o.IsSet {
		return defaultVal
	}
	return o.Val
}

func (o Optional[T]) MarshalJSON() ([]byte, error) {
	if !o.IsSet {
		return []byte("null"), nil
	}
	return json.Marshal(o.Val)
}

func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		o.IsSet = false
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.IsSet = true
	o.Val = v
	return nil
}

// Scan implements the SQL driver.Scanner interface.
func (o *Optional[T]) Scan(value any) error {
	if value == nil {
		o.IsSet = false
		return nil
	}

	var v T
	switch t := any(&v).(type) {
	case interface{ Scan(any) error }:
		if err := t.Scan(value); err != nil {
			return err
		}
	default:
		v = value.(T)
	}

	o.Val = v
	o.IsSet = true

	return nil
}

// Value implements the driver Valuer interface.
func (o Optional[T]) Value() (driver.Value, error) {
	if !o.IsSet {
		return nil, nil
	}
	switch t := any(o.Val).(type) {
	case interface{ Value() (any, error) }:
		return t.Value()
	default:
		return o.Val, nil
	}
}

func (o Optional[T]) String() string {
	if !o.IsSet {
		return ""
	}

	return fmt.Sprintf("%v", o.Val)
}
