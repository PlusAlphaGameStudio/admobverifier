package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"fmt"
	"github.com/joho/godotenv"
	"google.golang.org/api/option"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func initializeAppWithServiceAccount() *firebase.App {

	credFilePath := os.Getenv("ADMOB_VERIFIER_CRED_FILE_PATH")
	log.Print(credFilePath)

	opt := option.WithCredentialsFile(credFilePath)
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	return app
}

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
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
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
		_, _ = fmt.Fprintln(w, "Reward Verified and Processed!")
	} else {
		http.Error(w, "Invalid Request", http.StatusForbidden)
	}
}

func accessServicesSingleApp(app *firebase.App) (*messaging.Client, error) {
	client, err := app.Messaging(context.Background())
	if err != nil {
		log.Fatalf("error getting Auth client: %v\n", err)
	}

	return client, err
}

var messagingClient *messaging.Client

func main() {
	goDotErr := godotenv.Load()
	if goDotErr != nil {
		log.Println("Error loading .env file")
	}

	var app *firebase.App

	app = initializeAppWithServiceAccount()

	var err error

	messagingClient, err = accessServicesSingleApp(app)
	if err != nil {
		panic(errors.New(fmt.Sprintf("messaging client init failed: %s", err.Error())))
	}

	testMessage()

	http.HandleFunc("/reward", rewardHandler)
	_ = http.ListenAndServe(":60340", nil)
}

func testMessage() {


	token := os.Getenv("ADMOB_VERIFIER_TEST_TOKEN")
	message := &messaging.Message{
		Token: token,
		Data: map[string]string{
			"보낸 시각": time.Now().String(),
			"점수": "850",
			"시간": "2:45",
		},
	}

	// Send a message to the device corresponding to the provided
	// registration token.
	response, err := messagingClient.Send(context.Background(), message)
	if err != nil {
		panic(errors.New(fmt.Sprintf("test message send failed")))
	}

	log.Println(response)
}
