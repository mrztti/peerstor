package impl

import (
	"sync"
)

type AtomicCounter struct {
	sync.RWMutex
	count uint
}

func (c *AtomicCounter) IncrementAndGet() uint {
	c.Lock()
	defer c.Unlock()
	c.count++
	return c.count
}

func (c *AtomicCounter) DecrementAndGet() uint {
	c.Lock()
	defer c.Unlock()
	c.count--
	return c.count
}

func (c *AtomicCounter) Get() uint {
	c.RLock()
	defer c.RUnlock()
	return c.count
}

func (c *AtomicCounter) Set(newCount uint) uint {
	c.Lock()
	c.count = newCount
	defer c.Unlock()
	return c.count
}

func (c *AtomicCounter) SetToMax(maybeNewCount uint) uint {
	c.Lock()
	defer c.Unlock()
	if maybeNewCount > c.count {
		c.count = maybeNewCount
	}
	return c.count
}

type CBool struct {
	sync.RWMutex
	val bool
}

func (c *CBool) Get() bool {
	c.RLock()
	defer c.RUnlock()
	return c.val
}

func (c *CBool) Set(newval bool) {
	c.Lock()
	defer c.Unlock()
	c.val = newval
}
