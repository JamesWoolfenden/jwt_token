package main

import (
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"context"
	"encoding/json"
	"fmt"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/google/uuid"
	"hash/crc32"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"
)

type token struct {
	Kid     string `json:"kid"`
	Secret  string `json:"secret"`
	Created int64  `json:"created_at"`
}

func init() {
	functions.HTTP("jwtUpdater", jwtUpdater)
}

// btDeleter is an HTTP Cloud Function with a request parameter.
func jwtUpdater(w http.ResponseWriter, r *http.Request) {
	jwt()
}

func main() {
	jwt()
}

func jwt() error {

	ProjectID := GetProjectID()
	var myToken token

	myToken.Secret = RandomString(64)
	myToken.Created = time.Now().Unix()
	id := uuid.New()
	myToken.Kid = id.String()

	result, _ := json.Marshal(myToken)
	log.Print(string(result))
	Name := "TEST_JGW"

	secretID := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", ProjectID, Name)
	secret, err := GetSecret(secretID)

	if err != nil {
		fmt.Printf(`{"message": "Failed to retrieve secret", "severity": "error"}`)
		log.Fatalf("failed to retrieve secret %s", secretID)
	}

	var parsed []token
	json.Unmarshal(secret, &parsed)

	combined := append([]token{myToken}, parsed...)

	results, _ := json.MarshalIndent(combined, "", "  ")

	postSecretID := fmt.Sprintf("projects/%s/secrets/%s", ProjectID, Name)

	err = addSecretVersion(postSecretID, results)

	if err != nil {
		fmt.Print(err)
		fmt.Printf(`{"message": "Failed to update secret", "severity": "error"}`)
		return err
	}

	fmt.Printf(`{"message": "Updated secret", "severity": "info"}`)
	return nil
}

func RandomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func GetSecret(secret string) ([]byte, error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("failed to setup client: %v", err)
	}
	defer client.Close()

	getSecretReq := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secret,
	}

	it, err := client.AccessSecretVersion(ctx, getSecretReq)

	if err != nil {
		return nil, err
	}

	return it.Payload.Data, nil
}

func addSecretVersion(secret string, payload []byte) error {

	// Compute checksum, use Castagnoli polynomial. Providing a checksum
	// is optional.
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(payload, crc32c))

	// Create the client.
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	defer client.Close()

	// Build the request.
	req := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret,
		Payload: &secretmanagerpb.SecretPayload{
			Data:       payload,
			DataCrc32C: &checksum,
		},
	}

	// Call the API.
	result, err := client.AddSecretVersion(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to add secret version: %w", err)
	}

	log.Print(result)
	return nil
}

func GetProjectID() string {
	url := "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		fmt.Printf(`{"message": "Failed to retieve metadata", "severity": "warning"}`)
		return "122203615305"
	}

	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	passed := fmt.Sprintf(string(body))

	fmt.Printf(`{"message": "ProjectID %s", "severity": "info"}`, passed)
	return passed
}
