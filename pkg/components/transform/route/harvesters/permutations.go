package harvesters

func Permutations[T any](arr []T, n int) [][]T {
	var res [][]T
	var generate func([]T, []T, []bool)
	generate = func(path, rest []T, used []bool) {
		if len(path) > n {
			return
		}
		if len(path) > 0 {
			// Make a copy of path to avoid aliasing
			cp := append([]T{}, path...)
			res = append(res, cp)
		}
		for i := 0; i < len(rest); i++ {
			if !used[i] {
				used[i] = true
				next := append([]T{}, rest[:i]...)
				next = append(next, rest[i+1:]...)
				generate(append(path, rest[i]), next, used)
				used[i] = false
			}
		}
	}
	used := make([]bool, len(arr))
	generate([]T{}, arr, used)
	return res
}
