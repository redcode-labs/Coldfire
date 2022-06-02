package coldfire

import (
	"math/rand"
	"net"
	"reflect"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"github.com/c-robinson/iplib"
)

// RemoveFromSlice removes a string from a list of strings if it exists.
func RemoveFromSlice(slice []string, element string) []string {
	res := []string{}

	for _, e := range slice {
		if e != element {
			res = append(res, e)
		}
	}

	return res
}

// CreateWordList generates possible variations of each word in the wordlist.
func CreateWordlist(words []string) []string {
	wordlist := []string{}
	for _, w := range words {
		word := w
		first_to_upper := strings.ToUpper(string(word[0])) + string(word[1:])
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, Revert(word))
		wordlist = append(wordlist, first_to_upper)
		wordlist = append(wordlist, first_to_upper+"1")
		wordlist = append(wordlist, first_to_upper+"12")
		wordlist = append(wordlist, first_to_upper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
	}

	return wordlist
}

// RemoveStr removes a given string from a list of strings.
func RemoveStr(slice []string, s string) []string {
	final := []string{}
	for _, e := range slice {
		if e != s {
			final = append(final, e)
		}
	}

	return final
}

// RemoveInt removes a given integer from a list of integers.
func RemoveInt(slice []int, s int) []int {
	final := []int{}
	for _, e := range slice {
		if e != s {
			final = append(final, e)
		}
	}

	return final
}

// SplitJoin splits a string then joins them using given delimiters.
func SplitJoin(s, splittBy, joinBy string) string {
	splitted := strings.Split(s, splittBy)
	joined := strings.Join(splitted, joinBy)

	return joined
}

// RevertSlice reverses a slice type agnostically.
func RevertSlice(s interface{}) {
	n := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)

	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func SplitMultiSep(s string, seps []string) []string {
	f := func(c rune) bool {
		for _, sep := range seps {
			if string(c) == sep {
				return true
			}
		}
		return false
	}
	fields := strings.FieldsFunc(s, f)
	return fields
}

func SplitChunks(s string, chunk int) []string {
	if chunk >= len(s) {
		return []string{s}
	}
	var chunks []string
	c := make([]rune, chunk)
	len := 0
	for _, r := range s {
		c[len] = r
		len++
		if len == chunk {
			chunks = append(chunks, string(c))
			len = 0
		}
	}
	if len > 0 {
		chunks = append(chunks, string(c[:len]))
	}
	return chunks
}

// ExtractIntFromString extracts a list of possible integers from a given string.
func ExtractIntFromString(s string) []int {
	res := []int{}
	re := regexp.MustCompile(`[-]?\d[\d,]*[\.]?[\d{2}]*`)
	submatchall := re.FindAllString(s, -1)

	for _, element := range submatchall {
		res = append(res, StrToInt(element))
	}

	return res
}

// ShuffleSlice randomly shuffles a list of strings.
func ShuffleSlice(s []string) []string {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(s), func(i, j int) {
		s[i], s[j] = s[j], s[i]
	})

	return s
}

// IpIncrement increments an IP address by 1.
func IpIncrement(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Revert returns a reversed string.
func Revert(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// Contains is used to check if an element exists in an array type agnostically.
func Contains(s interface{}, elem interface{}) bool {
	arrV := reflect.ValueOf(s)
	if arrV.Kind() == reflect.Slice {
		for i := 0; i < arrV.Len(); i++ {
			if arrV.Index(i).Interface() == elem {
				return true
			}
		}
	}
	return false
}

// StrToWords returns a list of strings which was split by spaces.
func StrToWords(s string) []string {
	words := []string{}
	gr := strings.Split(s, " ")
	for x := range gr {
		z := gr[x]
		if len(z) != 0 {
			words = append(words, z)
		}
	}
	return words
}

// SizeToBytes converts a human friendly string indicating size into a proper integer.
func SizeToBytes(size string) int {
	period_letter := string(size[len(size)-1])
	intr := string(size[:len(size)-1])
	i, _ := strconv.Atoi(intr)
	switch period_letter {
	case "g":
		return i * 1024 * 1024 * 1024
	case "m":
		return i * 1024 * 1024
	case "k":
		return i * 1024
	}
	return i
}

// IntervalToSeconds converts a human friendly string indicating time into a proper integer.
func IntervalToSeconds(interval string) int {
	period_letter := string(interval[len(interval)-1])
	intr := string(interval[:len(interval)-1])
	i, _ := strconv.Atoi(intr)

	switch period_letter {
	case "s":
		return i
	case "m":
		return i * 60
	case "h":
		return i * 3600
	case "d":
		return i * 24 * 3600
	}
	return i
}

// RemoveNewLines removes possible newlines from a string.
func RemoveNewlines(s string) string {
	re := regexp.MustCompile(`\r?\n`)
	s = re.ReplaceAllString(s, " ")
	return s
}

// FullRemove removes all instances of a string from another string.
func FullRemove(str string, to_remove string) string {
	return strings.Replace(str, to_remove, "", -1)
}

// RemoveDuplicatesStr returns an array of strings that are unique to each other.
func RemoveDuplicatesStr(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// RemoveDuplicatesInt returns an array of integers that are unique to each other.
func RemoveDuplicatesInt(slice []int) []int {
	keys := make(map[int]bool)
	list := []int{}

	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// ContainsAny checks if a string exists within a list of strings.
func ContainsAny(str string, elements []string) bool {
	for element := range elements {
		e := elements[element]
		if strings.Contains(str, e) {
			return true
		}
	}

	return false
}

// Convert an IPv4 address to hex 
func IP2Hex(ip string) string {
	ip_obj := net.ParseIP(ip)
	return iplib.IPToHexString(ip_obj)
}

// Convert a port to hex
func Port2Hex(port int) string {
	hexval := fmt.Sprintf("0x%x", port)
	hexval_without_prefix := FullRemove(hexval, "0x")
	two_bytes_slice := SplitChunks(hexval_without_prefix, 2)
	return fmt.Sprintf("0x%s%s", two_bytes_slice[1], two_bytes_slice[0])
}