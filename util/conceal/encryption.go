package conceal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// PKCS5Padding adds padding to the plaintext to make it a multiple of the block size
func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// Encrypt encrypts the plaintext,the input salt should be a random string that is appended to the plaintext
// that gets fed into the one-way function that hashes it.
func Encrypt(plaintext, salt string) (string, error) {
	h := sha256.New()
	h.Write([]byte(os.Getenv("SECRET")))
	key := h.Sum(nil)
	plaintextBytes := PKCS5Padding([]byte(plaintext), aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintextBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintextBytes)
	// return hexadecimal representation of the ciphertext
	return hex.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertext, salt string) (string, error) {

	h := sha256.New()
	// have to check if the secret is hex encoded
	h.Write([]byte(os.Getenv("SECRET") + salt))
	key := h.Sum(nil)
	ciphertext_bytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := ciphertext_bytes[:aes.BlockSize]
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	ciphertext_bytes = ciphertext_bytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext_bytes, ciphertext_bytes)
	plaintext := PKCS5UnPadding(ciphertext_bytes)
	return string(plaintext), nil
}
