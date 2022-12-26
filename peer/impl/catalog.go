package impl

import (
	"fmt"

	"go.dedis.ch/cs438/peer"
)

type CatalogInside struct {
	peer.ConcurrentMap[struct{}]
}

func (r *CatalogInside) GetRandomEntry(forbiddenKeys peer.Set[string]) (string, error) {
	if r.Count() <= len(forbiddenKeys) {
		return "", fmt.Errorf("no more keys available")
	}
	r.RLock()
	defer r.RUnlock()
	// This is not guaranteed to be truly random, but I think it should suffice for our purposes
	for key := range r.Items {
		if !forbiddenKeys.Has(key) {
			return key, nil
		}
	}
	return "", fmt.Errorf("no more keys available")
}

type ConcurrentCatalog struct {
	peer.ConcurrentMap[*CatalogInside]
	addr string
}

func CreateConcurrentCatalog(addr string) ConcurrentCatalog {
	return ConcurrentCatalog{
		ConcurrentMap: peer.CreateConcurrentMap[*CatalogInside](),
		addr:          addr,
	}
}

func (c *ConcurrentCatalog) UpdateCatalog(key string, newPeer string) {
	c.Lock()
	maybeFile, ok := c.Items[key]
	if !ok {
		newCatalogInside := CatalogInside{peer.CreateConcurrentMap[struct{}]()}
		maybeFile = &newCatalogInside
		c.Items[key] = maybeFile
	}
	c.Unlock()
	maybeFile.Set(newPeer, struct{}{})
}

func (c *ConcurrentCatalog) GetCatalog() peer.Catalog {
	tmp := make(map[string]map[string]struct{})
	c.RLock()
	defer c.RUnlock()
	for key, value := range c.Items {
		tmp[key] = value.GetCopy()
	}
	return tmp
}

func (c *ConcurrentCatalog) GetRandomEntryFor(key string) (string, error) {
	c.RLock()
	defer c.RUnlock()
	maybeFile, ok := c.Items[key]
	if !ok {
		return "", fmt.Errorf("entry for key not found")
	}
	return maybeFile.GetRandomEntry(peer.NewSet[string]())
}

func (c *ConcurrentCatalog) RemoveEntryFor(key, peerToRemove string) error {
	c.RLock()
	defer c.RUnlock()
	maybeFile, ok := c.Items[key]
	if !ok {
		return fmt.Errorf("entry for key not found")
	}
	maybeFile.Remove(peerToRemove)
	return nil
}
