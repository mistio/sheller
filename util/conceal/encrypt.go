package conceal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
)

// PKCS5Padding adds padding to the plaintext to make it a multiple of the block size
func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// Encrypt encrypts the plaintext,the input salt should be a random string that is appended to the plaintext
// that gets fed into the one-way function that hashes it.
func Encrypt(plaintext, salt string) string {
	h := sha256.New()
	h.Write([]byte(os.Getenv("SECRET")))
	key := h.Sum(nil)
	plaintextBytes := PKCS5Padding([]byte(plaintext), aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextBytes)
	// return hexadecimal representation of the ciphertext
	return hex.EncodeToString(ciphertext)
}
