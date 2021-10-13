package coldfire

import (
	"math/rand"
	"time"
)

// RandomSelectStr returns a string that was randomly selected from a list of strings.
func RandomSelectStr(list []string) string {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

// RandomSelectStrNested returns a string array that was randomly selected from a nested list of strings
func RandomSelectStrNested(list [][]string) []string {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

// RandomSelectInt returns an integer that was randomly selected from a list of integers.
func RandomSelectInt(list []int) int {
	rand.Seed(time.Now().UnixNano())
	return list[rand.Intn(len(list))]
}

// RandomString randomly generates an alphabetic string of a given length.
func RandomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)

	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return string(b)
}
