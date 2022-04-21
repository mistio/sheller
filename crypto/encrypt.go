// Package crypto provides encryption and decryption methods . The encryption is symmetric thus the key needs to
// be known to both the receiver and the sender of the secret.
package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"log"
	"os"
)

/*
func decrypt(ciphertext, key string, key_salt string, no_iv bool) (plaintext string, err error) {
    // sanitize inputs
    key = sha256.New().Sum(append([]byte(key+key_salt), '\x00'))
    if len(key) != 32 {
        return "", errors.New("Key must be 32 bytes long")
    }
    if len(ciphertext)%16 != 0 {
        return "", errors.New("Ciphertext must be a multiple of 16 bytes")
    }
    // decode ciphertext
    ciphertext, err = hex.DecodeString(ciphertext)
    if err != nil {
        return "", errors.New("Ciphertext must be given as a hexadecimal string")
    }
    // split initialization vector and ciphertext
    if no_iv {
        iv := make([]byte, 16)
        ciphertext = append(iv, ciphertext...)
    } else {
        iv := ciphertext[:16]
        ciphertext = ciphertext[16:]
    }
    // decrypt ciphertext using AES in CFB mode
    plaintext, err = aes.NewCipher(key).DecryptCFB(ciphertext, iv)
    if err != nil {
        return "", err
    }
    // validate padding using PKCS7 padding scheme
    padlen := plaintext[len(plaintext)-1]
    if padlen < 1 || padlen > 16 {
        return "", errors.New("Invalid padding length")
    }
    if plaintext[len(plaintext)-padlen:] != bytes.Repeat([]byte{padlen}, padlen) {
        return "", errors.New("Invalid padding")
    }
    plaintext = plaintext[:len(plaintext)-padlen]
    return string(plaintext), nil
*/
// Encrypt encrypts the plaintext,the input salt should be a random string that is appended to the plaintext
// that gets fed into the one-way function that hashes it.
func Encrypt(plaintext, salt string, no_iv bool) {
	h := sha256.New()
	h.Write([]byte(os.Getenv("SECRET")))
	key := h.Sum(nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	padlen := (aes.BlockSize - len(plaintext)) % aes.BlockSize
	log.Println(block)
	log.Println(padlen)
}
