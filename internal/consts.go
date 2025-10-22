package internal

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0a4471"
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// unused for now
	ZeroTierSNI   = "zt-masque.cloudflareclient.com"
	ConnectURI    = "https://cloudflareaccess.com"
	DefaultModel  = "PC"
	KeyTypeWg     = "curve25519"
	TunTypeWg     = "wireguard"
	KeyTypeMasque = "secp256r1"
	TunTypeMasque = "masque"
	DefaultLocale = "en_US"
	//
	VersionHeader   = "cf-client-version"
	ConnectProtocol = "cf-connect-ip"
	ConnectVersion  = "a-6.35-4471"
)

var Headers = map[string]string{
	"User-Agent":   "WARP for Android",
	VersionHeader:  ConnectVersion,
	"Content-Type": "application/json; charset=UTF-8",
	"Connection":   "Keep-Alive",
}
