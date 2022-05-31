package coldfire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
	"bytes"
)

func GenerateKey() []byte {
	random_bytes := make([]byte, 32)
	_, err := crand.Read(random_bytes) // Generates 32 cryptographically secure random bytes
	if err != nil {
		println("Failed to generate the key.")
		return nil
	}
	return random_bytes
}

func GenerateIV() []byte {
	random_bytes := make([]byte, 16)
	_, err := crand.Read(random_bytes) // Generates 16 cryptographically secure random bytes
	if err != nil {
		println("Failed to generate IV.")
		return nil
	}
	return random_bytes
}

func EncryptBytes(secret_message []byte, key []byte) []byte {
	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		println("Error occured, can't encrypt")
		return nil
	}

	length_to_bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(length_to_bytes, uint32(len(secret_message)))

	length_and_secret := append(length_to_bytes, secret_message...)

	IV := GenerateIV()
	if len(length_and_secret)%16 != 0 {
		appending := make([]byte, (16 - len(length_and_secret)%16))
		corrected := append(length_and_secret, appending...)
		length_and_secret = corrected
	}

	c := cipher.NewCBCEncrypter(cipher_block, IV)
	encrypted := make([]byte, len(length_and_secret))
	c.CryptBlocks(encrypted, length_and_secret)

	return append(IV, encrypted...)
}

func DecryptBytes(encrypted_message []byte, key []byte) []byte {
	IV := encrypted_message[0:16]

	actual_ciphertext := encrypted_message[16:]

	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		println("Error occured, can't decrypt")
	}
	c := cipher.NewCBCDecrypter(cipher_block, IV)
	decrypted := make([]byte, len(actual_ciphertext))
	c.CryptBlocks(decrypted, actual_ciphertext)

	length_bytes := decrypted[0:4]
	length := binary.LittleEndian.Uint32(length_bytes)
	decrypted = decrypted[4:]
	return decrypted[:length]
}

func EncryptString(message string, key []byte) []byte {
	return DecryptBytes([]byte(message), key)
}

func DecryptString(encrypted_message []byte, key []byte) string {
	return string(DecryptBytes(encrypted_message, key))
}

// MD5Hash hashes a given string using the MD5.
func Md5Hash(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))

	return hex.EncodeToString(hasher.Sum(nil))
}

//SHA1Hash hashes a given string using the SHA1.
func Sha1Hash(str string) string {
	hasher := sha1.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

func Sha256Hash(str string) string {
	hasher := sha256.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

// B64D decodes a given string encoded in Base64.
func B64D(str string) string {
	raw, _ := base64.StdEncoding.DecodeString(str)

	return fmt.Sprintf("%s", raw)
}

// B64E encodes a string in Base64.
func B64E(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func Rot13(str string) string{
	var finaldata bytes.Buffer
	for _, character := range str {
		if character >= 'a' && character <= 'z' {
			if character > 'm' {
				character_tmp := character - 13
				finaldata.WriteString(string(character_tmp))
			} else if character == 'm' {
				character_tmp := 'z'
				finaldata.WriteString(string(character_tmp))
			} else if character == 'z' {
				character_tmp := 'm'
				finaldata.WriteString(string(character_tmp))
			} else {
				character_tmp := character + 13
				finaldata.WriteString(string(character_tmp))
			}
		}else if character >= 'A' && character <= 'Z' {
			if character > 'M' {
				character_tmp := character - 13
				finaldata.WriteString(string(character_tmp))
			} else if character == 'M' {
				character_tmp := 'Z'
				finaldata.WriteString(string(character_tmp))
			}else if character == 'Z'{
				character_tmp := 'M'
				finaldata.WriteString(string(character_tmp))
			} else {
				character_tmp := character + 13
				finaldata.WriteString(string(character_tmp))
			}
		}
	}
	return finaldata.String()
}

func UnixToTime(time_num int64) string{
	return time.Unix(time_num, 0).String()
}

