package models

type APIResponse struct {
	Result  *any      `json:"result,omitempty"`
	Success bool      `json:"success"`
	Errors  APIErrors `json:"errors"`
}

type AccountResponse struct {
	Result *AccountData `json:"result,omitempty"`
	APIResponse
}
