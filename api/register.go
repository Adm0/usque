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
//   - pubKey: []byte - The new MASQUE public key in binary format.
//   - name: string - The name of the device. (optional)
//   - model: string - The device model string to register. (e.g., "PC")
//   - jwt: string - Team token to register.
//
// Returns:
//   - models.Registration: The device data returned from the registration process.
//   - error:              An error if registration fails at any step.
func Register(pubKey []byte, name string, model string, jwt string) (*models.Registration, error) {
	data := models.RegistrationData{
		Type:    internal.Platform,
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		Tos:     internal.TimeAsCfString(time.Now()),
		Model:   model,
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
		Name:    name,
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

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	var respData models.RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("server response code: %v (%d)", resp.Status, resp.StatusCode)
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !respData.Success {
		return nil, &respData.Errors
	}

	return respData.Result, nil
}

// EnrollKey updates an existing user account with a new MASQUE public key.
//
// This function sends a PATCH request to update the user's account with a new key.
//
// Parameters:
//   - pubKey: []byte - The new MASQUE public key in binary format.
//   - name: string - The name of the device to enroll. (optional)
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - models.Registration: The updated device registration.
//   - error:              An error if the update process fails.
func EnrollKey(pubKey []byte, name string, deviceId string, deviceToken string) (*models.Registration, error) {
	deviceUpdate := models.EnrollData{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
		Name:    name,
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(http.MethodPatch, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	var respData models.RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("server response code: %v (%d)", resp.Status, resp.StatusCode)
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !respData.Success {
		return nil, &respData.Errors
	}

	return respData.Result, nil
}
