package http

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	Writer http.ResponseWriter
}

func (r *Response) SetStatus(code StatusCode) {
	r.Writer.WriteHeader(int(code))
}

func (r *Response) SetHeader(key, value string) {
	r.Writer.Header().Set(key, value)
}

func (r *Response) SetCookie(cookie Cookie) {
	http.SetCookie(r.Writer, &http.Cookie{
		Name:     cookie.Name,
		Value:    cookie.Value,
		Path:     cookie.Path,
		Domain:   cookie.Domain,
		MaxAge:   cookie.MaxAge,
		Secure:   cookie.Secure,
		HttpOnly: cookie.HttpOnly,
		SameSite: http.SameSite(cookie.SameSite),
	})
}

func (r *Response) Write(data []byte) (int, error) {
	return r.Writer.Write(data)
}

func (r *Response) SendText(text string) error {
	r.Writer.Header().Set("Content-Type", "text/plain")
	_, err := r.Writer.Write([]byte(text))
	return err
}

func (r *Response) SendJSON(data any) error {
	r.Writer.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(r.Writer).Encode(data)
}

func (r *Response) SendRedirect(url string, code StatusCode) error {
	r.SetHeader("Location", url)
	r.SetStatus(code)
	return nil
}

func (r *Response) SetNoCacheHeaders() {
	r.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	r.Writer.Header().Set("Pragma", "no-cache")
	r.Writer.Header().Set("Expires", "0")
}
