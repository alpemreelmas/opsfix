package adapter

import (
	"fmt"
	"sync"
)

var globalRegistry = &registry{
	adapters: map[string]Adapter{},
}

type registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

func Register(a Adapter) {
	if a.InterfaceVersion() != InterfaceVersion {
		panic(fmt.Sprintf("adapter %q: interface version mismatch (got %d, want %d)",
			a.ID(), a.InterfaceVersion(), InterfaceVersion))
	}
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	if _, exists := globalRegistry.adapters[a.ID()]; exists {
		panic(fmt.Sprintf("adapter %q already registered", a.ID()))
	}
	globalRegistry.adapters[a.ID()] = a
}

func All() []Adapter {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	out := make([]Adapter, 0, len(globalRegistry.adapters))
	for _, a := range globalRegistry.adapters {
		out = append(out, a)
	}
	return out
}

// ToolIndex returns a map of tool name -> adapter
func ToolIndex() map[string]Adapter {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	idx := make(map[string]Adapter)
	for _, a := range globalRegistry.adapters {
		for _, t := range a.Tools() {
			idx[t.Name] = a
		}
	}
	return idx
}

// AllTools returns all ToolDefinitions from all registered adapters
func AllTools() []ToolDefinition {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	var defs []ToolDefinition
	for _, a := range globalRegistry.adapters {
		defs = append(defs, a.Tools()...)
	}
	return defs
}
