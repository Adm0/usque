package models

type AccountData struct {
	License string `json:"license,omitempty"`
}

type AccountResponse struct {
	Result *Account `json:"result,omitempty"`
	APIResponse
}

type DevicesResponse struct {
	Result *Devices `json:"result,omitempty"`
	APIResponse
}

type Account struct {
	ID          string `json:"id"`
	AccountType string `json:"account_type,omitempty"`
	// Created not set for ZeroTier
	Created string `json:"created,omitempty"`
	// Updated not set for ZeroTier
	Updated string `json:"updated,omitempty"`
	// Managed only set for ZeroTier
	Managed string `json:"managed,omitempty"`
	// Organization only set for ZeroTier
	Organization string `json:"organization,omitempty"`
	// PremiumData not set for ZeroTier
	PremiumData int `json:"premium_data,omitempty"`
	// Quota not set for ZeroTier
	Quota int `json:"quota,omitempty"`
	// WarpPlus not set for ZeroTier
	WarpPlus bool `json:"warp_plus,omitempty"`
	// ReferralCode not set for ZeroTier
	ReferralCount int `json:"referral_count,omitempty"`
	// ReferralRenewalCount not set for ZeroTier
	ReferralRenewalCount int `json:"referral_renewal_countdown,omitempty"`
	// Role not set for ZeroTier
	Role string `json:"role,omitempty"`
	// License not set for ZeroTier
	License string `json:"license,omitempty"`
}

type Devices []Device

type Device struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Model     string `json:"model"`
	Name      string `json:"name"`
	Created   string `json:"created"`
	Activated string `json:"activated"`
	Active    bool   `json:"active"`
	Role      string `json:"role"`
}
