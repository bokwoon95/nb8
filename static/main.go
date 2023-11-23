package main

import "fmt"

func main() {
	for _, last := range []int{100, 50, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		fmt.Printf("last: %d\n", last)
		for current := last; current >= 1; current-- {
			numbers := paginate(current, last)
			fmt.Printf("  current: %d, numbers: %+v\n", current, numbers)
		}
	}
}

func paginate(current, last int) []string {
	var numbers []string
	return numbers
}
