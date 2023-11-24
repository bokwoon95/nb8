package main

import (
	"fmt"
	"strconv"
)

func main() {
	for _, last := range []int{100, 50, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		fmt.Printf("last: %d\n", last)
		for current := last; current >= 1; current-- {
			var numbers []int
			unit := last / 10
			if last <= 15 {
				numbers = make([]int, 0, last)
				for i := 1; i <= last; i++ {
					numbers = append(numbers, i)
				}
			} else {
				numbers = []int{
					0:  current - max(unit, 5),
					1:  current - max(unit/2, 4),
					2:  current - max(unit/4, 3),
					3:  current - 2,
					4:  current - 1,
					5:  current,
					6:  current + 1,
					7:  current + 2,
					8:  current + max(unit/4, 3),
					9:  current + max(unit/2, 4),
					10: current + max(unit, 5),
				}
			}
			result := make([]string, len(numbers))
			for i := 0; i < len(numbers); i++ {
				if numbers[i] == current {
					result[i] = "(" + strconv.Itoa(numbers[i]) + ")"
				} else {
					result[i] = strconv.Itoa(numbers[i])
				}
			}
			fmt.Printf("  %+v\n", result)
		}
	}
}
