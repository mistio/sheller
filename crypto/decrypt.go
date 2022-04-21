package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"os"
)

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
func decrypt(ciphertext string, no_iv bool) string {
	// have to check if the secret is hex encoded
	key := []byte(os.Getenv("SECRET"))
	ciphertext_bytes, _ := hex.DecodeString(ciphertext)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	iv := ciphertext_bytes[:aes.BlockSize]
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	ciphertext_bytes = ciphertext_bytes[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext_bytes, ciphertext_bytes)
	plaintext := string(PKCS5UnPadding(ciphertext_bytes))
	return plaintext
}
