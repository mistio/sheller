package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

var vaultAddr = "http://127.0.0.1:8200" // only for development
var loginAddr = "/v1/auth/approle/login"

type AppRoleLoginPayload struct {
	Role_id   string `json:"role_id"`
	Secret_id string `json:"secret_id"`
}

type AppRoleClientToken struct {
	Token         string
	TokenDuration time.Duration
}

func (AppRoleLoginPayload *AppRoleLoginPayload) Login() AppRoleClientToken {
	payload, err := json.Marshal(AppRoleLoginPayload)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := http.Post(vaultAddr+loginAddr, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		log.Fatal(err)
	}
	var result map[string]map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&result)
	return AppRoleClientToken{Token: result["auth"]["client_token"].(string), TokenDuration: time.Duration(result["auth"]["token_duration"].(time.Duration))}
}
