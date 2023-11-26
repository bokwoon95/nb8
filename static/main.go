package main

import (
	"fmt"
	"strconv"
)

//

func main() {
	for _, last := range []int{8005, 100, 50, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		fmt.Printf("last: %d\n", last)
		for current := last; current >= 1; current = current >> 1 {
			printResult(paginate(current, last, 9), current)
		}
	}
}

func paginate(currentPage, lastPage, visiblePages int) []int {
	const numConsecutiveNeighbours = 2
	if lastPage <= visiblePages {
		slots := make([]int, 0, lastPage)
		for page := 1; page <= lastPage; page++ {
			slots = append(slots, page)
		}
		return slots
	}
	if visiblePages%2 == 0 {
		panic("even number of visiblePages")
	}
	minVisiblePages := (numConsecutiveNeighbours * 2) + 1
	if visiblePages < minVisiblePages {
		panic("visiblePages cannot be lower than " + strconv.Itoa(minVisiblePages))
	}
	slots := make([]int, visiblePages)
	unit := lastPage / 10
	if currentPage-1 < visiblePages>>1 {
		numConsecutive := (currentPage - 1) + 1 + numConsecutiveNeighbours
		consecutiveStart := 0
		consecutiveEnd := numConsecutive - 1
		page := 1
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		slots[len(slots)-1] = lastPage
		remainingSlots := slots[consecutiveEnd+1 : len(slots)-1]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else if lastPage-currentPage < visiblePages>>1 {
		numConsecutive := (lastPage - currentPage) + 1 + numConsecutiveNeighbours
		consecutiveStart := len(slots) - 1
		consecutiveEnd := len(slots) - numConsecutive
		page := lastPage
		for i := consecutiveStart; i >= consecutiveEnd; i-- {
			slots[i] = page
			page -= 1
		}
		slots[0] = 1
		remainingSlots := slots[1:consecutiveEnd]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveEnd; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else {
		consecutiveStart := visiblePages>>1 - numConsecutiveNeighbours
		consecutiveEnd := visiblePages>>1 + numConsecutiveNeighbours
		page := currentPage - numConsecutiveNeighbours
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		slots[0] = 1
		remainingSlots := slots[1:consecutiveStart]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveStart; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
		remainingSlots = slots[consecutiveEnd+1 : len(slots)-1]
		delta = numConsecutiveNeighbours + len(remainingSlots)
		shift = 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
		slots[len(slots)-1] = lastPage
	}
	return slots
}

func printResult(slots []int, current int) {
	result := make([]string, len(slots))
	for i := 0; i < len(slots); i++ {
		if slots[i] == current {
			result[i] = "(" + strconv.Itoa(slots[i]) + ")"
		} else {
			result[i] = strconv.Itoa(slots[i])
		}
	}
	fmt.Printf("  %+v\n", result)
}
