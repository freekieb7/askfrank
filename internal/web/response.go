package web

import (
	"fmt"
	"net/http"
	"time"
)

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
