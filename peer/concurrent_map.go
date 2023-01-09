package peer

import (
	"sync"
)

// Inspired by the  orcaman / concurrent-map package but with sharding removed

// A "thread" safe string to anything map.
type ConcurrentMap[V any] struct {
	Items map[string]V
	sync.RWMutex
}

// Creates a new concurrent map.
func CreateConcurrentMap[V any]() ConcurrentMap[V] {
	return ConcurrentMap[V]{Items: make(map[string]V)}
}

// Sets the given value under the specified key.
func (m *ConcurrentMap[V]) Set(key string, value V) {
	m.Lock()
	m.Items[key] = value
	m.Unlock()
}

// Returns the value under the specified key if it exists.
// If not, sets it to value and returns that.
func (m *ConcurrentMap[V]) GetOrSetIfNonExistent(key string, value V) V {
	m.Lock()
	defer m.Unlock()
	maybeValue, ok := m.Items[key]
	if ok {
		return maybeValue
	}
	m.Items[key] = value
	return value
}

// Get retrieves an element from map under given key.
func (m *ConcurrentMap[V]) Get(key string) (V, bool) {
	m.RLock()
	val, ok := m.Items[key]
	m.RUnlock()
	return val, ok
}

func (m *ConcurrentMap[V]) GetKeys() []string {
	m.RLock()
	defer m.RUnlock()
	keys := make([]string, len(m.Items))
	i := 0
	for k := range m.Items {
		keys[i] = k
		i++
	}
	return keys
}

// Count returns the number of elements within the map.
func (m *ConcurrentMap[V]) Count() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.Items)
}

// Looks up an item under specified key
func (m *ConcurrentMap[V]) Has(key string) bool {
	m.RLock()
	_, ok := m.Items[key]
	m.RUnlock()
	return ok
}

// Remove removes an element from the map.
func (m *ConcurrentMap[V]) Remove(key string) {
	m.Lock()
	delete(m.Items, key)
	m.Unlock()
}

// IsEmpty checks if map is empty.
func (m *ConcurrentMap[V]) IsEmpty() bool {
	return m.Count() == 0
}

// GetCopy returns all items as map[string]V
func (m *ConcurrentMap[V]) GetCopy() map[string]V {
	tmp := make(map[string]V)
	m.RLock()
	defer m.RUnlock()
	for key, value := range m.Items {
		tmp[key] = value
	}
	return tmp
}

func (m *ConcurrentMap[V]) ForEach(Process func(V)) {
	m.Lock()
	defer m.Unlock()
	for _, value := range m.Items {
		Process(value)
	}
}
