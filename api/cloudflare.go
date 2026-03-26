package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// Register creates a new user account by registering a WireGuard public key and generating a random Android-like device identifier.
// The WireGuard private key isn't stored anywhere, therefore it won't be usable. It's sole purpose is to mimic the Android app's registration process.
//
// This function sends a POST request to the API to register a new user and returns the created account data.
//
// Parameters:
//   - model: string - The device model string to register. (e.g., "PC")
//   - locale: string - The user's locale. (e.g., "en-US")
//   - jwt: string - Team token to register.
//   - acceptTos: bool - Whether the user accepts the Terms of Service (TOS). If false, the user will be prompted to accept.
//
// Returns:
//   - models.AccountData: The account data returned from the registration process.
//   - error:              An error if registration fails at any step.
//
// Example:
//
//	account, err := Register("PC", "en-US", "", false)
//	if err != nil {
//	    log.Fatalf("Registration failed: %v", err)
//	}
func Register(pubKey []byte, deviceName string, model string, jwt string, acceptTos bool) (*models.AccountData, error) {
	var err error

	if !acceptTos {
		fmt.Print("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return nil, fmt.Errorf("failed to read user input: %v", err)
		}
		if response != "y" {
			return nil, fmt.Errorf("user did not accept TOS")
		}
	}

	data := models.Registration{
		Type:    "windows",
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		Tos:     internal.TimeAsCfString(time.Now()),
		Model:   model,
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
		Name:    deviceName,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, internal.ApiUrl+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	var respData models.AccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("server response code: %v (%d)", resp.Status, resp.StatusCode)
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !respData.Success {
		return nil, fmt.Errorf("failed to complete API request: %w", &respData.Errors)
	}

	return respData.Result, nil
}

// EnrollKey updates an existing user account with a new MASQUE public key.
//
// This function sends a PATCH request to update the user's account with a new key.
//
// Parameters:
//   - pubKey: []byte - The new MASQUE public key in binary format.
//   - deviceName: string - The name of the device to enroll. (optional)
//   - accountId: string - The account user ID
//   - accountToken: string - The account user access token
//
// Returns:
//   - models.AccountData: The updated account data.
//   - error:              An error if the update process fails.
//
// Example:
//
//	updatedAccount, apiErr, err := EnrollKey(account, pubKey, "PC")
//	if err != nil {
//	    log.Fatalf("Key enrollment failed: %v", err)
//	}
func EnrollKey(pubKey []byte, deviceName string, accountId string, accountToken string) (*models.AccountData, error) {
	deviceUpdate := models.Registration{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
		Name:    deviceName,
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(http.MethodPatch, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+accountId, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	var respData models.AccountResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to register: %v (%d)", resp.Status, resp.StatusCode)
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !respData.Success {
		return nil, fmt.Errorf("failed to complete API request: %w", &respData.Errors)
	}

	return respData.Result, nil
}
