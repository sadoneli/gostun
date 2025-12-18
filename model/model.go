package model

import "github.com/pion/logging"

const GoStunVersion = "v0.0.5"

var (
	AddrStr              = "stun.miwifi.com:3478"
	Timeout              = 3
	Verbose              = 0
	UDPSendCount         = 2
	Log                  logging.LeveledLogger
	NatMappingBehavior   string
	NatFilteringBehavior string
	EnableLoger          = true
	IPVersion            = "ipv4"
	BindInterface        = ""
)

func GetDefaultServers(IPVersion string) []string {
	switch IPVersion {
	case "ipv6":
		return []string{
			"stun.hot-chilli.net:3478",
			"stun.ipfire.org:3478",
			"stun.flashdance.cx:3478",
			"stun.cloudflare.com:3478",
			"stun.f.haeder.net:3478",
			"stun.l.google.com:19302",
		}
	case "ipv4":
		return []string{
			"stun.miwifi.com:3478",
			"stun.fitauto.ru:3478",
			"stun.hot-chilli.net:3478",
			"stun.nextcloud.com:3478",
			"stun.nextcloud.com:443",
			"stun.ringostat.com:3478",
			"stun.romaaeterna.nl:3478",
			"stun.telnyx.com:3478",
			"stun.sonetel.net:3478",
			"stun.radiojar.com:3478",
			"stun.sip.us:3478",
			"stun.pure-ip.com:3478",
			"stun.bethesda.net:3478",
		}
	default:
		return []string{
			"stun.miwifi.com:3478",
			"stun.fitauto.ru:3478",
			"stun.hot-chilli.net:3478",
			"stun.nextcloud.com:3478",
			"stun.nextcloud.com:443",
			"stun.ringostat.com:3478",
			"stun.romaaeterna.nl:3478",
			"stun.telnyx.com:3478",
			"stun.sonetel.net:3478",
			"stun.radiojar.com:3478",
			"stun.sip.us:3478",
			"stun.pure-ip.com:3478",
			"stun.bethesda.net:3478",
		}
	}
}
