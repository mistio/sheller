package conceal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
)

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
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
