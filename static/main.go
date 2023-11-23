package main

import (
	"fmt"
	"strconv"
)

func main() {
	for _, last := range []int{100, 50, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		fmt.Printf("last: %d\n", last)
		for current := last; current >= 1; current-- {
			numbers := paginate(current, last)
			fmt.Printf("  %+v\n", numbers)
		}
	}
}

func paginate(current, last int) []string {
	var numbers []int
	unit := last / 10
	if unit/4 < 1 {
		numbers = make([]int, 0, last)
		for i := 1; i <= last; i++ {
			numbers = append(numbers, i)
		}
	} else {
		numbers = make([]int, 11)
		numbers[0] = current - unit
		numbers[1] = current - (unit / 2)
		numbers[2] = current - (unit / 4)
		numbers[3] = current - 2
		numbers[4] = current - 1
		numbers[5] = current
		numbers[6] = current + 1
		numbers[7] = current + 2
		numbers[8] = current + (unit / 4)
		numbers[9] = current + (unit / 2)
		numbers[10] = current + unit
	}
	result := make([]string, len(numbers))
	for i := 0; i < len(numbers); i++ {
		if i < 1 || i > last {
			result[i] = "-"
		} else if i == current {
			result[i] = "(" + strconv.Itoa(i) + ")"
		} else {
			result[i] = strconv.Itoa(i)
		}
	}
	return result
}
