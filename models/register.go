package models

type RegistrationData struct {
	Type    string `json:"type"`
	Model   string `json:"model"`
	Tos     string `json:"tos"`
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

type EnrollData struct {
	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	TunType string `json:"tunnel_type"`
	Name    string `json:"name,omitempty"`
}

type RegistrationResponse struct {
	Result *Registration `json:"result,omitempty"`
	APIResponse
}

type Registration struct {
	ID      string  `json:"id"`
	Type    string  `json:"type"`
	Model   string  `json:"model"`
	Name    string  `json:"name"`
	Key     string  `json:"key"`
	KeyType string  `json:"key_type"`
	TunType string  `json:"tunnel_type"`
	Account Account `json:"account"`
	Config  Config  `json:"config"`
	// WarpEnabled not set for ZeroTier
	WarpEnabled bool `json:"warp_enabled,omitempty"`
	// Waitlist not set for ZeroTier
	Waitlist bool   `json:"waitlist_enabled,omitempty"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
	// Tos not set for ZeroTier
	Tos string `json:"tos,omitempty"`
	// Place not set for ZeroTier
	Place  int    `json:"place,omitempty"`
	Locale string `json:"locale"`
	// Enabled not set for ZeroTier
	Enabled   bool   `json:"enabled,omitempty"`
	InstallID string `json:"install_id"`
	// Token only set for /reg call
	Token    string `json:"token,omitempty"`
	FcmToken string `json:"fcm_token"`
	// SerialNumber not set for ZeroTier
	SerialNumber string `json:"serial_number,omitempty"`
	Policy       Policy `json:"policy"`
}

type Config struct {
	ClientID  string `json:"client_id"`
	Peers     []Peer `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Services struct {
		HTTPProxy string `json:"http_proxy"`
	} `json:"services"`
}

type Peer struct {
	PublicKey string `json:"public_key"`
	Endpoint  struct {
		V4    string `json:"v4"`
		V6    string `json:"v6"`
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	} `json:"endpoint"`
}

type Policy struct {
	TunnelProtocol string `json:"tunnel_protocol"`
	// TODO: add ZeroTier fields
}
