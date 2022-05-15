package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func CheckMAC(mac string, message string, secret []byte) error {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	if sha != mac {
		return fmt.Errorf("Invalid MAC")
	}
	return nil
}
