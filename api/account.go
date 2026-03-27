package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// GetAccount Retrieves information about the license key associated with the device.
//
// This function sends GET request to receiving account information.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - *models.Account: The account information.
//   - error:           An error if the request fails.
func GetAccount(deviceId string, deviceToken string) (*models.Account, error) {
	req, err := http.NewRequest(http.MethodGet, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

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
		return nil, &respData.Errors
	}

	return respData.Result, nil
}

// UpdateLicenceKey changes the key associated with the device to a new one.
//
// This function sends a PUT request to update device licence key.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//   - licenceKey: string - New licence key
//
// Returns:
//   - error: An error if the request fails.
func UpdateLicenceKey(deviceId string, deviceToken string, licenceKey string) error {
	deviceUpdate := models.AccountData{
		License: licenceKey,
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var respData models.APIResponse
		if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
			return fmt.Errorf("server response code: %v (%d)", resp.Status, resp.StatusCode)
		}
		return &respData.Errors
	}

	return nil
}

// DeleteLicenceKey Resets the currently bound key.
//
// This function sends DELETE request to delete device licence key.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - error: An error if the request fails.
func DeleteLicenceKey(deviceId string, deviceToken string) error {
	req, err := http.NewRequest(http.MethodDelete, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		var respData models.APIResponse
		if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
			return fmt.Errorf("server response code: %v (%d)", resp.Status, resp.StatusCode)
		}
		return &respData.Errors
	}

	return nil
}

// GetDevice Gets information about devices associated with the same licence key.
//
// This function sends GET request to receiving devices information.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - *models.Devices: The account devices information.
//   - error:           An error if the request fails.
func GetDevices(deviceId string, deviceToken string) (*models.Devices, error) {
	req, err := http.NewRequest(http.MethodGet, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account/devices", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	var respData models.DevicesResponse
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
