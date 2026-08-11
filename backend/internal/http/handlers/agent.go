package handlers

import (
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"net/http"
)

type Agent struct{}

func (Agent) Heartbeat(w http.ResponseWriter, r *http.Request) {
	middleware.JSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "accepted"}})
}
func (Agent) NextJob(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
func (Agent) JobState(w http.ResponseWriter, r *http.Request) {
	middleware.JSON(w, http.StatusAccepted, map[string]any{"data": map[string]string{"status": "accepted"}})
}
