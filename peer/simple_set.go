package peer

// Largely taken from https://dbuddy.medium.com/implementing-set-data-structure-in-go-using-generics-4a967f823bfb
type Set[T comparable] map[T]bool

func NewSet[T comparable](values ...T) Set[T] {
	set := make(Set[T])
	set.Add(values...)
	return set
}

func (s Set[T]) Add(values ...T) {
	for _, value := range values {
		s[value] = true
	}
}

func (s Set[T]) Delete(values ...T) {
	for _, value := range values {
		delete(s, value)
	}
}

func (s Set[T]) Len() int {
	return len(s)
}

func (s Set[T]) Has(value T) bool {
	_, ok := s[value]
	return ok
}

func (s Set[T]) Iterate(iterator func(T)) {
	for v := range s {
		iterator(v)
	}
}

func (s *Set[T]) Values() []T {
	values := make([]T, 0)
	s.Iterate(func(value T) {
		values = append(values, value)
	})
	return values
}

func (s *Set[T]) Clone() Set[T] {
	set := make(Set[T])
	set.Add(s.Values()...)
	return set
}

func (s *Set[T]) Union(other Set[T]) Set[T] {
	set := s.Clone()
	set.Add(other.Values()...)
	return set
}

func (s *Set[T]) Intersection(other Set[T]) Set[T] {
	set := make(Set[T])
	s.Iterate(func(value T) {
		if other.Has(value) {
			set.Add(value)
		}
	})
	return set
}
