# QUIC over Yggdrasil

This package allows you to set up QUIC sessions natively over the
Yggdrasil Network. This is in place of using a TUN adapter or IPv6
and allows Yggdrasil-native applications to be built easily.

See `yggquic_test.go` for example usage.

To build a library for [Mimir](https://mimir-app.net) use:
```shell
# One time:
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
# And then every rebuild:
gomobile bind -tags "noprofiler" -ldflags="-s -w" -target=android -androidapi 23 -javapkg=com.revertron.mimir -o yggquic.aar ./mobile
```
