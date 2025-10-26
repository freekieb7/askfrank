package http

import (
	"encoding/json"
	"net/http"
)

type Method string

const (
	MethodGet     Method = "GET"
	MethodPost    Method = "POST"
	MethodPut     Method = "PUT"
	MethodDelete  Method = "DELETE"
	MethodPatch   Method = "PATCH"
	MethodOptions Method = "OPTIONS"
	MethodHead    Method = "HEAD"
	MethodTrace   Method = "TRACE"
)

type Request struct {
	Request *http.Request
}

func (r *Request) Header(key string) string {
	return r.Request.Header.Get(key)
}

func (r *Request) Method() Method {
	return Method(r.Request.Method)
}

func (r *Request) Cookie(name string) (*http.Cookie, error) {
	return r.Request.Cookie(name)
}

func (r *Request) UserAgent() string {
	return r.Request.UserAgent()
}

func (r *Request) RemoteAddr() string {
	return r.Request.RemoteAddr
}

func (r *Request) URLPathValue(key string) string {
	return r.Request.PathValue(key)
}

func (r *Request) URLQueryParam(key string) string {
	return r.Request.URL.Query().Get(key)
}

func (r *Request) FormValue(key string) string {
	return r.Request.FormValue(key)
}

func (r *Request) DecodeJSON(v any) error {
	return json.NewDecoder(r.Request.Body).Decode(v)
}

func (r *Request) URL() string {
	return r.Request.URL.String()
}

func (r *Request) URLPath() string {
	return r.Request.URL.Path
}
