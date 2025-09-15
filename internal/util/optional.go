package util

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

type Optional[T any] struct {
	Data T
	Some bool
}

func Some[T any](v T) Optional[T] {
	return Optional[T]{Data: v, Some: true}
}

func None[T any]() Optional[T] {
	return Optional[T]{}
}

func (o Optional[T]) Unwrap() T {
	if !o.Some {
		panic("called Unwrap on a None value")
	}
	return o.Data
}

func (o Optional[T]) UnwrapOr(defaultVal T) T {
	if !o.Some {
		return defaultVal
	}
	return o.Data
}

func (o Optional[T]) MarshalJSON() ([]byte, error) {
	if !o.Some {
		return []byte("null"), nil
	}
	return json.Marshal(o.Data)
}

func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		o.Some = false
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.Data = v
	return nil
}

// Scan implements the SQL driver.Scanner interface.
func (o *Optional[T]) Scan(value any) error {
	if value == nil {
		o.Some = false
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

	o.Data = v
	o.Some = true

	return nil
}

// Value implements the driver Valuer interface.
func (o Optional[T]) Value() (driver.Value, error) {
	if !o.Some {
		return nil, nil
	}
	switch t := any(o.Data).(type) {
	case interface{ Value() (any, error) }:
		return t.Value()
	default:
		return o.Data, nil
	}
}

func (o Optional[T]) String() string {
	if !o.Some {
		return ""
	}

	return fmt.Sprintf("%v", o.Data)
}
