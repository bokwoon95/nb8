package main

import (
	"fmt"
	"strconv"
)

//

func main() {
	for _, last := range []int{100, 50, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		fmt.Printf("last: %d\n", last)
		for current := last; current >= 1; current-- {
			if last <= 15 {
				slots := make([]int, 0, last)
				for i := 1; i <= last; i++ {
					slots = append(slots, i)
				}
				printResult(slots, current)
				continue
			}
			slots := make([]int, 15)
			// A unit is a tenth of the maximum number of pages. The rationale
			// is that users have to paginate at most 10 such units to get from
			// start to end, no matter how many pages there are.
			unit := last / 10
			if current-1 < 7 {
				// Number of consecutively incrementing page numbers from left
				// to right.
				numConsecutive := (current - 1) + 3
				// Fill in the consecutive slots from left to right with
				// incrementing page numbers starting from 1.
				consecutiveStart := 0
				consecutiveEnd := numConsecutive - 1
				pageNumber := 1
				for i := consecutiveStart; i <= consecutiveEnd; i++ {
					slots[i] = pageNumber
					pageNumber += 1
				}
				// Last slot is always the last page.
				slots[len(slots)-1] = last
				// Fill in the remaining slots with this algorithm: going from
				// right to left, the slot to the left of the last slot is
				// (current + unit). And the slot to the left of that is
				// (current + unit/2). And slot to the left of that is (current
				// + unit/4), then (current + unit/8), and so on and so forth.
				//
				// However: page numbers must also, at bare minimum, be
				// increasing by 1 from left to right. If (current + unit/n)
				// ever ends up being lower than the naturally increasing page
				// number, we must pick the naturally increasing page number
				// instead.
				remainingSlots := slots[consecutiveEnd+1 : len(slots)-1]
				delta := 2 + len(remainingSlots)
				shift := 0
				for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
					slots[i] = current + max(unit>>shift, delta)
					shift += 1
					delta -= 1
				}
			} else if last-current < 7 {
				// Number of consecutively decrementing page numbers from right
				// to left.
				numConsecutive := (last - current) + 3
				// Fill in the consecutive slots from right to left with
				// decrementing page numbers starting from last.
				consecutiveStart := len(slots) - 1
				consecutiveEnd := len(slots) - numConsecutive
				pageNumber := last
				for i := consecutiveStart; i >= consecutiveEnd; i-- {
					slots[i] = pageNumber
					pageNumber -= 1
				}
				// First slot is always the first page.
				slots[0] = 1
				// Fill in the remaining slots with this algorithm: going from
				// left to right, the slot to the right of the first slot is
				// (current - unit). And to the right of that is (current -
				// unit/2). And the slot to the right of that is (current -
				// unit/4), then (current - unit/8), and so on and so forth.
				//
				// However: page numbers must also, at bare minimum, be
				// increasing by 1 from left to right. If (current + unit/n)
				// ever ends up being lower than the naturally increasing page
				// number, we must pick the naturally increasing page number
				// instead.
				remainingSlots := slots[1:consecutiveEnd]
				delta := 2 + len(remainingSlots)
				shift := 0
				for i := 1; i < consecutiveEnd; i++ {
					slots[i] = current - max(unit>>shift, delta)
					shift += 1
					delta -= 1
				}
			} else {
				slots[0] = 1
				slots[1] = current - max(unit>>0, 6)
				slots[2] = current - max(unit>>1, 5)
				slots[3] = current - max(unit>>2, 4)
				slots[4] = current - max(unit>>3, 3)
				slots[5] = current - 2
				slots[6] = current - 1
				slots[7] = current
				slots[8] = current + 1
				slots[9] = current + 2
				slots[10] = current + max(unit>>3, 3)
				slots[11] = current + max(unit>>2, 4)
				slots[12] = current + max(unit>>1, 5)
				slots[13] = current + max(unit>>0, 6)
				slots[14] = last
			}
			printResult(slots, current)
		}
	}
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

func paginate(currentPage, lastPage, visiblePages int) []int {
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
	if visiblePages < 5 {
		panic("visiblePages cannot be lower than 5")
	}
	slots := make([]int, visiblePages)
	// A unit is a tenth of the maximum number of pages. This is so that users
	// have to paginate at most 10 such units to get from start to end, no
	// matter how many pages there are.
	unit := lastPage / 10
	if currentPage-1 < visiblePages>>1 {
		currentSlot := -1
		page := 1
		for i := 0; i < len(slots); i++ {
			slots[i] = page
			page += 1
			if page == currentPage {
				currentSlot = i
			}
		}
		altSlots := make([]int, len(slots[currentSlot+2:len(slots)-1]))
		shift := 0
		for i := len(altSlots) - 1; i >= 0; i-- {
			altSlots[i] = currentPage + unit>>shift
			shift += 1
		}
		for i, j := currentSlot+2, 0; i < len(slots) && j < len(altSlots); i, j = i+1, j+1 {
			slots[i] = max(slots[i], altSlots[j])
		}
		slots[len(slots)-1] = lastPage
	} else if lastPage-currentPage < visiblePages>>1 {
		currentSlot := -1
		page := lastPage
		for i := len(slots) - 1; i >= 0; i-- {
			slots[i] = page
			page -= 1
			if page == currentPage {
				currentSlot = i
			}
		}
		altSlots := make([]int, len(slots[1:currentSlot-2]))
		shift := 0
		for i := len(altSlots) - 1; i >= 0; i++ {
			altSlots[i] = currentPage - unit>>shift
			shift += 1
		}
		for i, j := 1, 0; i < len(slots) && j < len(altSlots); i, j = i+1, j+1 {
			slots[i] = max(slots[i], altSlots[i])
		}
		slots[0] = 1
	} else {
		currentSlot := (visiblePages >> 1) + 1

		page := currentPage
		for i := currentSlot; i >= 0; i-- {
			slots[i] = page
			page -= 1
		}
		leftAltSlots := make([]int, len(slots[1:currentSlot-2]))
		shift := 0
		for i := 0; i < len(leftAltSlots); i++ {
			leftAltSlots[i] = currentPage - unit>>shift
			shift += 1
		}
		for i, j := 1, 0; i < len(slots) && j < len(leftAltSlots); i, j = i+1, j+1 {
			slots[i] = max(slots[i], leftAltSlots[i])
		}
		slots[0] = 1

		page = currentPage
		for i := currentSlot; i < len(slots); i++ {
			slots[i] = page
			page += 1
		}
		rightAltSlots := make([]int, len(slots[currentSlot+3:len(slots)-1]))
		shift = 0
		for i := len(rightAltSlots) - 1; i >= 0; i-- {
			rightAltSlots[i] = currentPage + unit>>shift
		}
		for i, j := currentSlot+3, 0; i < len(slots) && j < len(rightAltSlots); i, j = i+1, j+1 {
			slots[i] = max(slots[i], rightAltSlots[j])
		}
		slots[len(slots)-1] = lastPage
	}
	return slots
}
