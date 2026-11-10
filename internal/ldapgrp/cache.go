package ldapgrp

import (
	"strings"
	"sync"
	"time"
)

// Cache guarda o resultado da resolução de grupos por usuário, para que uma
// rajada de eventos de logon do mesmo usuário não gere uma consulta LDAP cada.
type Cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]cacheEntry
}

type cacheEntry struct {
	logical  []string
	adGroups []string
	at       time.Time
	err      error
}

func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Cache{ttl: ttl, m: map[string]cacheEntry{}}
}

// SetTTL atualiza o tempo de validade (usado no SIGHUP).
func (c *Cache) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.ttl = ttl
	c.mu.Unlock()
}

// Get devolve a entrada em cache se ainda válida.
func (c *Cache) Get(user string) ([]string, []string, bool) {
	k := strings.ToLower(user)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok {
		return nil, nil, false
	}
	// Erros ficam em cache por um tempo bem menor, para não travar o usuário
	// caso o AD estivesse momentaneamente fora.
	ttl := c.ttl
	if e.err != nil {
		ttl = 60 * time.Second
	}
	if time.Since(e.at) > ttl {
		return nil, nil, false
	}
	return e.logical, e.adGroups, true
}

// Put grava uma resolução bem-sucedida.
func (c *Cache) Put(user string, logical, adGroups []string) {
	c.mu.Lock()
	c.m[strings.ToLower(user)] = cacheEntry{logical: logical, adGroups: adGroups, at: time.Now()}
	c.mu.Unlock()
}

// PutErr grava uma falha (cache curto).
func (c *Cache) PutErr(user string, err error) {
	c.mu.Lock()
	c.m[strings.ToLower(user)] = cacheEntry{err: err, at: time.Now()}
	c.mu.Unlock()
}

// Invalidate remove um usuário do cache.
func (c *Cache) Invalidate(user string) {
	c.mu.Lock()
	delete(c.m, strings.ToLower(user))
	c.mu.Unlock()
}

// Purge limpa todo o cache (SIGHUP, mudança de grupos).
func (c *Cache) Purge() {
	c.mu.Lock()
	c.m = map[string]cacheEntry{}
	c.mu.Unlock()
}
