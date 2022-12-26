package peer

import "sync"

type ConcurrentSet[T comparable] struct {
	Items map[T]bool
	sync.RWMutex
}

func CreateConcurrentSet[T comparable](values ...T) ConcurrentSet[T] {
	items := make(map[T]bool)
	for _, value := range values {
		items[value] = true
	}
	return ConcurrentSet[T]{Items: items}
}

func (s *ConcurrentSet[T]) Add(values ...T) {
	s.Lock()
	defer s.Unlock()
	for _, value := range values {
		s.Items[value] = true
	}
}

func (s *ConcurrentSet[T]) Delete(values ...T) {
	s.Lock()
	defer s.Unlock()
	for _, value := range values {
		delete(s.Items, value)
	}
}

func (s *ConcurrentSet[T]) Len() int {
	s.RLock()
	defer s.RUnlock()
	return len(s.Items)
}

func (s *ConcurrentSet[T]) Has(value T) bool {
	s.RLock()
	defer s.RUnlock()
	_, ok := s.Items[value]
	return ok
}

func (s *ConcurrentSet[T]) AddWithDuplicateCheck(value T) bool {
	s.Lock()
	defer s.Unlock()
	_, isDuplicate := s.Items[value]
	s.Items[value] = true
	return isDuplicate
}

func (s *ConcurrentSet[T]) Iterate(iterator func(T)) {
	s.RLock()
	defer s.RUnlock()
	for v := range s.Items {
		iterator(v)
	}
}

func (s *ConcurrentSet[T]) Values() []T {
	s.RLock()
	defer s.RUnlock()
	values := make([]T, 0)
	s.Iterate(func(value T) {
		values = append(values, value)
	})
	return values
}

func (s *ConcurrentSet[T]) Clone() ConcurrentSet[T] {
	s.RLock()
	defer s.RUnlock()
	return CreateConcurrentSet(s.Values()...)
}
