package ssh

import (
	"fmt"
	"sync"
	"time"

	"github.com/alperen/opsfix/internal/config"
)

type poolEntry struct {
	client   Client
	lastUsed time.Time
	healthy  bool
	cfg      config.ServerConfig
}

type Pool struct {
	mu          sync.RWMutex
	conns       map[string]*poolEntry
	sshCfg      config.SSHConfig
	done        chan struct{}
	serverIndex map[string]config.ServerConfig
}

func NewPool(servers []config.ServerConfig, sshCfg config.SSHConfig) *Pool {
	idx := make(map[string]config.ServerConfig, len(servers))
	for _, s := range servers {
		idx[s.Name] = s
	}

	p := &Pool{
		conns:       make(map[string]*poolEntry),
		sshCfg:      sshCfg,
		done:        make(chan struct{}),
		serverIndex: idx,
	}

	go p.reaper()
	return p
}

func (p *Pool) Get(serverName string) (Client, error) {
	p.mu.RLock()
	entry, ok := p.conns[serverName]
	if ok && entry.healthy {
		entry.lastUsed = time.Now()
		p.mu.RUnlock()
		return entry.client, nil
	}
	p.mu.RUnlock()

	// Need to create or recreate connection
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, ok := p.conns[serverName]; ok && entry.healthy {
		entry.lastUsed = time.Now()
		return entry.client, nil
	}

	srv, ok := p.serverIndex[serverName]
	if !ok {
		return nil, fmt.Errorf("ssh pool: unknown server %q", serverName)
	}

	c, err := dial(srv.Host, srv.Port, srv.User, srv.KeyPath, p.sshCfg.KnownHostsFile, p.sshCfg.ConnectTimeout)
	if err != nil {
		return nil, fmt.Errorf("ssh pool: connect to %q: %w", serverName, err)
	}

	p.conns[serverName] = &poolEntry{
		client:   c,
		lastUsed: time.Now(),
		healthy:  true,
		cfg:      srv,
	}

	return c, nil
}

func (p *Pool) Invalidate(serverName string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if entry, ok := p.conns[serverName]; ok {
		entry.client.Close()
		delete(p.conns, serverName)
	}
}

func (p *Pool) Close() {
	close(p.done)

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, entry := range p.conns {
		entry.client.Close()
	}
	p.conns = make(map[string]*poolEntry)
}

func (p *Pool) reaper() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			for name, entry := range p.conns {
				if time.Since(entry.lastUsed) > p.sshCfg.IdleTimeout {
					entry.client.Close()
					delete(p.conns, name)
				}
			}
			p.mu.Unlock()
		}
	}
}
