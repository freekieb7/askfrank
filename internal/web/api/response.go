package api

import (
	"encoding/json"
	"net/http"
)

type ErrorResponseBody struct {
	Error ErrorResponseBodyError `json:"error"`
}

type ErrorResponseBodyError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

func ErrorResponse(w http.ResponseWriter, status int, code int, message string) error {
	body := ErrorResponseBody{
		Error: ErrorResponseBodyError{
			Code:    code,
			Message: message,
			Status:  http.StatusText(status),
		},
	}
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(body)
}

func Redirect(w http.ResponseWriter, r *http.Request, urlStr string, code int) error {
	http.Redirect(w, r, urlStr, code)
	return nil
}
