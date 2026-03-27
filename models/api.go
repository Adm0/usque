package models

import (
	"fmt"
)

// Known error messages from the API
const (
	InvalidPublicKey      = 1001
	InvalidRegistrationId = 1013
	InvalidLicense        = 1046
	MethodNotAllowed      = 10000
)

type APIResponse struct {
	Result  *any      `json:"result,omitempty"`
	Success bool      `json:"success"`
	Errors  APIErrors `json:"errors"`
}

type APIErrors []APIError

// ErrorsAsString returns a string representation of the errors in the APIResponse.
// It concatenates the error messages into a single string, separated by semicolons.
//
// Parameters:
//   - separator: string - The string to use as a separator between error messages.
//
// Returns:
//   - string: A string containing all error messages, separated by the specified separator.
func (e *APIErrors) ErrorsAsString(separator string) string {
	var result string
	for _, err := range *e {
		result += err.Error() + separator
	}
	if len(result) > 0 {
		return result[:len(result)-len(separator)]
	}
	return result
}

// GetError get from APIResoinse a specific error code.
//
// Parameters:
//   - code: int - The error code to check for.
//
// Returns:
//   - *APIError: if the error code is found, otherwise nil.
func (e *APIErrors) Unwrap() []error {
	result := make([]error, len(*e))
	for i, err := range *e {
		result[i] = err
	}
	return result
}

// Error returns a string representation of the errors in the APIResponse.
//
// Returns:
//   - string: A string containing all error messages, separated by ', '.
func (e *APIErrors) Error() string {
	return e.ErrorsAsString(", ")
}

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error returns a string representation of the error.
//
// Returns:
//   - string: A string containing error message.
func (e APIError) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

func (e APIError) Is(value error) bool {
	if value, ok := value.(APIError); ok {
		return e.Code == value.Code
	}
	return false
}
