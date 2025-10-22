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
	ProtocolHeader  = "cf-connect-proto"
	VersionHeader   = "cf-client-version"
	ConnectProtocol = "cf-connect-ip"
	ConnectVersion  = "l-2025.8.779.0"
)

var Headers = map[string]string{
	"User-Agent":   "WARP for Linux",
	VersionHeader:  ConnectVersion,
	"Content-Type": "application/json; charset=UTF-8",
	"Connection":   "Keep-Alive",
}
