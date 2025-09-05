package harvesters

func Permutations2(arr []string) [][]string {
	var res [][]string

	for i := range arr {
		res = append(res, []string{arr[i]})
		for j := range arr {
			if i != j {
				res = append(res, []string{arr[i], arr[j]})
			}
		}
	}

	return res
}
