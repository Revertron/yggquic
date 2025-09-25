/*
 *  Copyright (c) 2025 Revertron
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package yggquic

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

type Messenger struct {
	transport *YggdrasilTransport
	cfg       *config.NodeConfig
	ctx       context.Context
	cancel    context.CancelFunc
}

type Conn struct {
	Stream net.Conn
	Public []byte // 32-byte remote public key
}

func (c *Conn) IsAlive() bool {
	if ys, ok := c.Stream.(*yggdrasilStream); ok {
		return ys.IsAlive()
	}
	return false
}

func (c *Conn) Close() {
	if ys, ok := c.Stream.(*yggdrasilStream); ok {
		err := ys.CloseConnection(quic.ApplicationErrorCode(0), "normal close")
		if err != nil {
			return
		}
	}
}

// NewMessenger creates a node and connects to the given bootstrap peer.
// peerAddr format: "tls://host:port" or any string accepted by yggdrasil.
func NewMessenger(peerAddr string) (*Messenger, error) {
	cfg := config.GenerateConfig()
	node, err := core.New(cfg.Certificate, nil)
	if err != nil {
		return nil, err
	}

	// add the bootstrap peer
	u, err := url.Parse(peerAddr)
	if err != nil {
		return nil, err
	}
	if err := node.AddPeer(u, ""); err != nil {
		return nil, err
	}

	tr, err := New(node, *cfg.Certificate, nil)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &Messenger{transport: tr, cfg: cfg, ctx: ctx, cancel: cancel}

	// wait a bit so the Yggdrasil connects
	time.Sleep(1 * time.Second)
	return m, nil
}

// NewWithNode lets callers supply their own *core.Core.
func NewWithNode(node *core.Core, cert *tls.Certificate, peerAddrs []string) (*Messenger, error) {
	for _, a := range peerAddrs {
		if a == "" {
			continue
		}
		u, err := url.Parse(a)
		if err != nil {
			return nil, err
		}
		if err := node.AddPeer(u, ""); err != nil {
			return nil, err
		}
	}
	tr, err := New(node, *cert, nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Messenger{transport: tr, cfg: &config.NodeConfig{Certificate: cert}, ctx: ctx, cancel: cancel}, nil
}

func (m *Messenger) PublicKey() []byte {
	return m.cfg.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
}

func (m *Messenger) Connect(publicKey []byte) (*Conn, error) {
	pub := make([]byte, len(publicKey))
	copy(pub, publicKey)
	keyHex := hex.EncodeToString(publicKey)
	stream, err := m.transport.Dial("yggdrasil", keyHex)
	if err != nil {
		return nil, err
	}
	return &Conn{Stream: stream, Public: pub}, nil
}

func (m *Messenger) Accept() (*Conn, error) {
	raw, err := m.transport.Accept()
	if err != nil {
		return nil, err
	}
	pub, _ := hex.DecodeString(raw.RemoteAddr().String())
	return &Conn{Stream: raw, Public: pub}, nil
}

func (m *Messenger) Close() error {
	m.cancel()
	return m.transport.Close()
}

// AddPeer adds a persistent peer from a string URI.
func (m *Messenger) AddPeer(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}
	corePtr := m.transport.yggdrasil.(*core.Core)
	return corePtr.AddPeer(u, "")
}

// RemovePeer removes a persistent peer from a string URI.
func (m *Messenger) RemovePeer(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}
	corePtr := m.transport.yggdrasil.(*core.Core)
	return corePtr.RemovePeer(u, "")
}

// RetryPeersNow forwards to the underlying Yggdrasil node.
func (m *Messenger) RetryPeersNow() {
	if core, ok := m.transport.yggdrasil.(*core.Core); ok {
		core.RetryPeersNow()
	}
}

// GetPeersJSON returns JSON peer list (same format as the old mobile helper).
func (m *Messenger) GetPeersJSON() string {
	type peerOut struct {
		core.PeerInfo
		IP string `json:"ip"`
	}

	corePtr := m.transport.yggdrasil.(*core.Core)
	var out []peerOut
	for _, p := range corePtr.GetPeers() {
		ip := ""
		if p.Key != nil {
			a := address.AddrForKey(p.Key)
			ip = net.IP(a[:]).String()
		}
		out = append(out, peerOut{PeerInfo: p, IP: ip})
	}

	if b, err := json.Marshal(out); err == nil {
		return string(b)
	}
	return "[]"
}

// GetPathsJSON returns JSON path list.
func (m *Messenger) GetPathsJSON() string {
	corePtr := m.transport.yggdrasil.(*core.Core)
	if b, err := json.Marshal(corePtr.GetPaths()); err == nil {
		return string(b)
	}
	return "[]"
}

// GetTreeJSON returns JSON tree info.
func (m *Messenger) GetTreeJSON() string {
	corePtr := m.transport.yggdrasil.(*core.Core)
	if b, err := json.Marshal(corePtr.GetTree()); err == nil {
		return string(b)
	}
	return "[]"
}
