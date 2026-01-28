module github.com/Revertron/yggquic

go 1.25.1

// https://github.com/DrewCyber/yggdrasil-go/tree/peer_state_callback
replace github.com/yggdrasil-network/yggdrasil-go => github.com/DrewCyber/yggdrasil-go v0.5.13-0.20260128175044-536f20de948e

require (
	github.com/Arceliar/ironwood v0.0.0-20260117132459-7017dbc41d8e
	github.com/quic-go/quic-go v0.59.0
	github.com/yggdrasil-network/yggdrasil-go v0.5.13-0.20251110194801-56044b822ba5
)

require (
	github.com/Arceliar/phony v0.0.0-20220903101357-530938a4b13d // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.7.1 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/gologme/log v1.3.0 // indirect
	github.com/hjson/hjson-go/v4 v4.5.0 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
)
