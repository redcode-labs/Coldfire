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

//RandomStringCharset returns a string of a given length from provided charset
func RandomStringCharset(strlen int, chars string) string {
	b := make([]byte, strlen)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// Returns a random true/false
func RandomBool() bool {
	rand.Seed(time.Now().UnixNano())
    return rand.Intn(2) == 1
}

// Creates and populates a slice with random numeric values up to 1000
func RandomIntSlice(length int) []int {
	var slc []int
    rand.Seed(time.Now().UnixNano())
    for i:=0; i<length; i++ {
        slc[i] = rand.Intn(1000)
    }
	return slc
}

func RandomFloatSlice(min, max float64, n int) []float64 {
    rand.Seed(time.Now().UnixNano())
    res := make([]float64, n)
    for i := range res {
        res[i] = min + rand.Float64() * (max - min)
    }
    return res
}