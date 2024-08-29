package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type VerifierKeys struct {
	Keys []struct {
		KeyId  int64  `json:"keyId"`
		Pem    string `json:"pem"`
		Base64 string `json:"base64"`
	} `json:"keys"`

	PublicKeys []*ecdsa.PublicKey
}

var publicKeys = make(map[int64]*ecdsa.PublicKey)
var lastPublicKeysUpdateTime = time.UnixMilli(0)

func fetchAdMobPublicKeys() {
	resp, err := http.Get("https://www.gstatic.com/admob/reward/verifier-keys.json")
	if err != nil {
		fmt.Println("Error fetching JSON:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	var keys VerifierKeys
	err = json.Unmarshal(body, &keys)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}

	fmt.Printf("Parsed Verifier Keys: %+v\n", keys)

	for _, key := range keys.Keys {
		block, _ := pem.Decode([]byte(key.Pem))
		if block == nil || block.Type != "PUBLIC KEY" {
			continue
		}
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}

		publicKeys[key.KeyId] = ecdsaPublicKey
	}
}

func verifySSVRequest(r *http.Request) bool {
	now := time.Now().UTC()

	publicKeysAge := now.Sub(lastPublicKeysUpdateTime)

	if publicKeysAge >= 24*time.Hour {
		fetchAdMobPublicKeys()
		lastPublicKeysUpdateTime = now
	}

	queryParams := r.URL.Query()

	signature := queryParams.Get("signature")
	if signature == "" {
		return false
	}

	signatureData := r.URL.RawQuery
	signatureData = signatureData[0:strings.Index(signatureData, "&signature=")]

	decodedData, err := url.QueryUnescape(signatureData)
	if err != nil {
		return false
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	hash := sha256.Sum256([]byte(decodedData))

	keyId, err := strconv.ParseInt(queryParams.Get("key_id"), 10, 64)
	if err != nil {
		return false
	}

	isValid := ecdsa.VerifyASN1(publicKeys[keyId], hash[:], signatureBytes)

	return isValid
}

func rewardHandler(w http.ResponseWriter, r *http.Request) {
	if verifySSVRequest(r) {
		fmt.Fprintln(w, "Reward Verified and Processed!")
	} else {
		http.Error(w, "Invalid Request", http.StatusForbidden)
	}
}

func main() {
	http.HandleFunc("/reward", rewardHandler)
	http.ListenAndServe(":60340", nil)
}
