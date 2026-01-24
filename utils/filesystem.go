package utils

import "strings"

func GetFilePath(fullpath string) string {
	separator := "\\"

	// 1. Split the string by the separator
	parts := strings.Split(fullpath, separator)

	if len(parts) > 1 {
		// 2. Slice the array to exclude the last element
		// The slicing operation `[:len(parts)-1]` creates a new slice
		// from the start (index 0) up to, but not including, the last element.
		partsWithoutLast := parts[:len(parts)-1]

		// 3. Join the remaining parts back into a single string using the same separator
		return strings.Join(partsWithoutLast, separator)
	} else {
		return ""
	}
}
