package internal

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0"
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// unused for now
	ZeroTierSNI   = "zt-masque.cloudflareclient.com"
	ConnectURI    = "http://cloudflareaccess.com"
	DefaultModel  = "PC"
	KeyTypeWg     = "curve25519"
	TunTypeWg     = "wireguard"
	KeyTypeMasque = "secp256r1"
	TunTypeMasque = "masque"
	DefaultLocale = "en_US"
	ClientVersion = "w-2026.1.150.0"
)

var Headers = map[string]string{
	"user-agent":        "WARP for Windows",
	"cf-client-version": ClientVersion,
	"content-type":      "application/json",
	"connection":        "Keep-Alive",
	"accept":            "*/*",
}
