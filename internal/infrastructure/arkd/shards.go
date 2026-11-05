package arkd

// shards spreads scripts over sets of at most size, so each fits one arkd subscription.
type shards struct {
	size  int
	sets  []map[string]struct{}
	where map[string]int // the set of each script
}

// place assigns scripts to sets with room, opening new ones as needed; the result lists the
// scripts added per set, new sets at the end.
func (s *shards) place(scripts []string) [][]string {
	if s.where == nil {
		s.where = make(map[string]int, len(scripts))
	}
	added := make([][]string, len(s.sets))
	for _, script := range scripts {
		if s.has(script) {
			continue
		}
		i := s.room()
		if i == len(s.sets) {
			s.sets = append(s.sets, make(map[string]struct{}, s.size))
			added = append(added, nil)
		}
		s.sets[i][script] = struct{}{}
		s.where[script] = i
		added[i] = append(added[i], script)
	}
	return added
}

func (s *shards) drop(scripts []string) [][]string {
	removed := make([][]string, len(s.sets))
	for _, script := range scripts {
		i, ok := s.where[script]
		if !ok {
			continue
		}
		delete(s.sets[i], script)
		delete(s.where, script)
		removed[i] = append(removed[i], script)
	}
	return removed
}

func (s *shards) scripts(i int) []string {
	out := make([]string, 0, len(s.sets[i]))
	for script := range s.sets[i] {
		out = append(out, script)
	}
	return out
}

func (s *shards) has(script string) bool {
	_, ok := s.where[script]
	return ok
}

func (s *shards) room() int {
	for i, set := range s.sets {
		if len(set) < s.size {
			return i
		}
	}
	return len(s.sets)
}
