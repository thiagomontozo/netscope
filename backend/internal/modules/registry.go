package modules

import (
	"errors"
	"fmt"
	"sync"

	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

type ParameterValidator interface{ Validate([]byte) error }
type Executor interface {
	Execute(ModuleContext) (RawResult, error)
}
type ResultParser interface {
	Parse(RawResult) ([]domain.Observation, []domain.Evidence, error)
}
type ModuleContext struct {
	Job    domain.AnalysisJob
	Target string
}
type RawResult struct {
	ContentType string
	Data        []byte
}
type Adapter struct {
	Definition domain.ModuleDefinition
	Validator  ParameterValidator
	Executor   Executor
	Parser     ResultParser
}
type Registry struct {
	mu      sync.RWMutex
	entries map[string]Adapter
}

func NewRegistry() *Registry { return &Registry{entries: make(map[string]Adapter)} }
func (r *Registry) Register(adapter Adapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if adapter.Definition.ID == "" || adapter.Validator == nil {
		return errors.New("module id and validator are required")
	}
	if _, exists := r.entries[adapter.Definition.ID]; exists {
		return fmt.Errorf("module %q already registered", adapter.Definition.ID)
	}
	r.entries[adapter.Definition.ID] = adapter
	return nil
}
func (r *Registry) Get(id string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	adapter, ok := r.entries[id]
	return adapter, ok
}
func (r *Registry) List() []domain.ModuleDefinition {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]domain.ModuleDefinition, 0, len(r.entries))
	for _, a := range r.entries {
		out = append(out, a.Definition)
	}
	return out
}
