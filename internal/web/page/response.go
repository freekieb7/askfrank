package page

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type APIResponseStatus string

const (
	APIResponseStatusSuccess APIResponseStatus = "success"
	APIResponseStatusError   APIResponseStatus = "error"
)

// Response body format for API
type JSONResponseBody struct {
	Status  APIResponseStatus `json:"status"`
	Message string            `json:"message,omitempty"`
	Data    any               `json:"data,omitempty"`
}

// JSONResponse writes a JSON response with the given status code and body.
func JSONResponse(w http.ResponseWriter, status int, body JSONResponseBody) error {
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(body)
}

func Redirect(w http.ResponseWriter, r *http.Request, urlStr string, code int) error {
	http.Redirect(w, r, urlStr, code)
	return nil
}

func Download(w http.ResponseWriter, r *http.Request, path, name string) error {
	f, err := http.Dir(path).Open(name)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Set headers
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set("Last-Modified", fi.ModTime().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))

	http.ServeContent(w, r, name, time.Now(), f)
	return nil
}
