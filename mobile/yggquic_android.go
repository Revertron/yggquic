package yggmobile

import (
	"time"

	"github.com/Revertron/yggquic"
)

type Messenger struct{ m *yggquic.Messenger }

// NewMessenger now takes a bootstrap peer address string.
func NewMessenger(peerAddr string) (*Messenger, error) {
	m, err := yggquic.NewMessenger(peerAddr)
	return &Messenger{m}, err
}

func (m *Messenger) PublicKey() []byte { return m.m.PublicKey() }
func (m *Messenger) Connect(pk []byte) (*Connection, error) {
	c, err := m.m.Connect(pk)
	if err != nil {
		return nil, err
	}
	return &Connection{c}, nil
}
func (m *Messenger) Accept() (*Connection, error) {
	c, err := m.m.Accept()
	if err != nil {
		return nil, err
	}
	return &Connection{c}, nil
}
func (m *Messenger) Close() error { return m.m.Close() }

// AddPeer forwards the string URI to the Go messenger.
func (m *Messenger) AddPeer(addr string) error {
	return m.m.AddPeer(addr)
}

// RemovePeer forwards the string URI to the Go messenger.
func (m *Messenger) RemovePeer(addr string) error {
	return m.m.RemovePeer(addr)
}

func (m *Messenger) RetryPeersNow() { m.m.RetryPeersNow() }

func (m *Messenger) GetPeersJSON() string { return m.m.GetPeersJSON() }
func (m *Messenger) GetPathsJSON() string { return m.m.GetPathsJSON() }
func (m *Messenger) GetTreeJSON() string  { return m.m.GetTreeJSON() }

type Connection struct{ c *yggquic.Conn }

func (c *Connection) PublicKey() []byte { return c.c.Public }
func (c *Connection) IsAlive() bool     { return c.c.IsAlive() }
func (c *Connection) Read(buf []byte) (int, error) {
	c.c.Stream.SetReadDeadline(time.Time{})
	return c.c.Stream.Read(buf)
}
func (c *Connection) ReadWithTimeout(buf []byte, timeoutMs int) (int, error) {
	c.c.Stream.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	return c.c.Stream.Read(buf)
}
func (c *Connection) Write(buf []byte) (int, error) {
	c.c.Stream.SetWriteDeadline(time.Time{})
	return c.c.Stream.Write(buf)
}
func (c *Connection) WriteWithTimeout(buf []byte, timeoutMs int) (int, error) {
	c.c.Stream.SetWriteDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	return c.c.Stream.Write(buf)
}
func (c *Connection) Close() { c.c.Close() }
