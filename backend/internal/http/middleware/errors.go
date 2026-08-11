package middleware

import (
	"encoding/json"
	"net/http"
)

type apiError struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"requestId"`
	} `json:"error"`
}

func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	var body apiError
	body.Error.Code = code
	body.Error.Message = message
	body.Error.RequestID = RequestIDFrom(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func JSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
