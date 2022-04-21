// Package crypto provides encryption and decryption methods . The encryption is symmetric thus the key needs to
// be known to both the receiver and the sender of the secret.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
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
	// have to check if the secret is hex encoded
	h.Write([]byte(os.Getenv("SECRET")))
	key := h.Sum(nil)
	plaintext_bytes := PKCS5Padding([]byte(plaintext), aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext_bytes)
	return fmt.Sprintf("%x", ciphertext)
}
