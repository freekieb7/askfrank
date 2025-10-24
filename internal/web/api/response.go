package api

import (
	"encoding/json"
	"net/http"
)

func ErrorResponse(w http.ResponseWriter, code int, status string, message string) error {
	body := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"status":  status,
		},
	}
	return JSONResponse(w, code, body)
}

func Redirect(w http.ResponseWriter, r *http.Request, urlStr string, code int) error {
	http.Redirect(w, r, urlStr, code)
	return nil
}

func PaginationResponse(w http.ResponseWriter, items any, nextPageToken string) error {
	body := map[string]any{
		"items":           items,
		"next_page_token": nextPageToken,
	}
	return JSONResponse(w, http.StatusOK, body)
}

func JSONResponse(w http.ResponseWriter, code int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	return json.NewEncoder(w).Encode(data)
}
