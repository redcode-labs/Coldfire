package coldfire

import (
	"math/rand"
	"net"
	"reflect"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"os"
	"bufio"
	"encoding/gob"
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

// Split a string by multiple sepaators to a single slice
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

// Applies a function to each element of a generic slice.
func SliceTransform(s []interface{}, f func(interface{}) interface{}){
	slen := reflect.ValueOf(s).Len()
	for i := 0; i < slen; i++ {
		s[i] = f(s[i])
	}
}

// Split string to a slice with chunks of desired length
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
		res = append(res, Str2Int(element))
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

// ShuffleSliceInt randomly shuffles a list of integers.
func ShuffleSliceInt(s []int) []int {
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

// Str2Words returns a list of strings which was split by spaces.
func Str2Words(s string) []string {
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

// Size2Bytes converts a human friendly string indicating size into a proper integer.
func Size2Bytes(size string) int {
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

// Interval2Seconds converts a human friendly string indicating time into a proper integer.
func Interval2Seconds(interval string) int {
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

// File2Slice reads a textfile and returns all lines as an array.
func File2Slice(file string) []string {
	fil, _ := os.Open(file)
	defer fil.Close()
	var lines []string
	scanner := bufio.NewScanner(fil)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
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

// Removes Nth index from generic slice if idx != 0; removes last element otherwise
func RemoveNth(slic interface{}, idx int) interface{}{
	slen := idx
	if (idx == 0){
		slen = reflect.ValueOf(slic).Len()
	}
	v := reflect.ValueOf(slic).Elem()
    v.Set(reflect.AppendSlice(v.Slice(0, slen), v.Slice(slen+1, v.Len())))
	return v
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

// Checks if a string exists within a list of strings.
func ContainsAny(str string, elements []string) bool {
	for element := range elements {
		e := elements[element]
		if strings.Contains(str, e) {
			return true
		}
	}
	return false
}

// Converts an IPv4 address to hex 
func IP2Hex(ip string) string {
	ip_obj := net.ParseIP(ip)
	return iplib.IPToHexString(ip_obj)
}

// Converts a port to hex
func Port2Hex(port int) string {
	hexval := fmt.Sprintf("0x%x", port)
	hexval_without_prefix := FullRemove(hexval, "0x")
	two_bytes_slice := SplitChunks(hexval_without_prefix, 2)
	return fmt.Sprintf("0x%s%s", two_bytes_slice[1], two_bytes_slice[0])
}

// Returns names of fields and their values in struct + names of fields with unitialized/empty values
// -1 value is treated as unitialized int field - you can change "val == -1" according to your needs
func Introspect(strct interface{}) (map[string]interface{}, []string) {
	nil_fields := []string{}
	strctret := make(map[string]interface{})
    strctval := reflect.ValueOf(strct)
    for i := 0; i < strctval.NumField(); i++ {
        val := strctval.Field(i).Interface()
        fld := strctval.Type().Field(i).Name
		strctret[fld] = val
		if (val == -1 || val == nil || val == ""){
			nil_fields = append(nil_fields, fld)
		}
    }
	return strctret, nil_fields
}

// Checks if a generic is iterable and non-emptty
func IsIterable(v interface{}) bool {
    return (reflect.TypeOf(v).Kind() == reflect.Slice && reflect.ValueOf(v).Len() >=1 )
}

// Generic boolean truth checker
func BoolCheck(boolean interface{}) bool {
	bval := reflect.ValueOf(boolean)
	slen := bval.Len()
	switch v := boolean.(type) {
		case []int:
			if slen != 0 {
				return true
			} 
		case []string:
			if slen != 0 {
				return true
			} 
		case []bool:
			if slen != 0 {
				return true
			} 
		case int:
			if bval.Int() == 1 {
				return true
			}
		case float64:
			if v == 0.0 {
				return true
			}
		case string:
			if slen == 0 {
				return true
			}
		case bool:
			if bval.Bool() {
				return true
			}
	}
	return false
}

// Unified serializer/deserializer for structs - logic is based on whether a .gob file already exists 
func Serializer(gobpath string, obj interface{}){
	if (Exists(gobpath)){
		gobfile, err := os.Open(gobpath)
		Check(err)
		decoder := gob.NewDecoder(gobfile)
		decoder.Decode(obj)
		gobfile.Close()
	} else {
		gobfile, err := os.Create(gobpath)
		Check(err)
		encoder := gob.NewEncoder(gobfile)
		encoder.Encode(obj)
		gobfile.Close()
	}
}

// Removes values from generics that do noe pass a truthcheck of f()
/*func Decimator[T any](s []T, f func(T) bool) []T {
	var r []T
	for _, v := range s {
	  if f(v) {
		r = append(r, v)
	  }
	}
	return r
}*/