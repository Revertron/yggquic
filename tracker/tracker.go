package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"

	//"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"github.com/Revertron/yggquic"
	//"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

const (
	version          = 1
	protoClient byte = 0x00
	protoSync   byte = 0x01
	cmdAnnounce      = 0
	cmdGetAddrs      = 1
	cmdSyncData      = 10 // remote pushes new record
	cmdSyncPing      = 20 // ping command

	maxHopCount = 3
)

var (
	// --- peer addresses given on CLI ---
	peerTrackers []string // hex-encoded ed25519 pub keys

	// --- outbound sync channels ---
	syncChan = make(chan syncItem, 512) // written by announce()

	// --- deduplication of very recent keys ---
	recentMu     sync.RWMutex
	recentUpdate = make(map[[32]byte]time.Time) // key -> last local update

	// Sync connections tracking
	connectedMu sync.Mutex
	connected   = map[[32]byte]struct{}{} // key = remote static pub key
)

type syncItem struct {
	key  [32]byte
	data record
	ttl  time.Time // When the item may be kept if peer is offline
	hop  int
}

const keyFile = "tracker.key"

// record stored for each user
type record struct {
	NodePub   [32]byte // key that announced
	Signature [64]byte // Signature of this addr
	Priority  byte
	ClientID  uint32
	Expires   time.Time
	PrevTtl   int
}

var (
	records   = make(map[[32]byte][]record) // userPub -> []record
	recordsMu sync.RWMutex
)

func main() {
	var (
		keyHex string
		peers  []string
	)
	fs := flag.NewFlagSet("tracker", flag.ExitOnError)
	fs.StringVar(&keyHex, "key", "", "hex-encoded 32-byte private key (optional)")
	fs.Func("peer", "bootstrap peer (can be given multiple times)", func(s string) error {
		peers = append(peers, s)
		return nil
	})
	fs.Func("server", "other tracker to sync with (can be given multiple times)", func(s string) error {
		peerTrackers = append(peerTrackers, s)
		return nil
	})
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
	if len(peers) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage:\n  %s -peer PEER1 [-peer PEER2 ...] [-key PRIV]\n", os.Args[0])
		os.Exit(1)
	}

	loadGob("data.gob", &records)
	defer saveGob("data.gob", records)

	var priv ed25519.PrivateKey
	if len(keyHex) > 0 {
		// second argument is hex private key
		var err error
		priv, err = hex.DecodeString(strings.TrimSpace(keyHex))
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			log.Fatalf("Invalid private key: %v", err)
		}
		log.Printf("Got tracker key - private: %x… public : %x\n", priv[:4], priv.Public())
	} else {
		// generate or load persistent key
		priv = loadOrGenKey()
	}

	// 1.  build a self-signed certificate
	pub := priv.Public().(ed25519.PublicKey)
	certDER, err := createSelfSignedCert(pub, priv)
	if err != nil {
		log.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER}, // ← required
		PrivateKey:  priv,
	}

	// 2.  use it everywhere
	node, err := core.New(&cert, nil)
	if err != nil {
		log.Fatal(err)
	}
	m, err := yggquic.NewWithNode(node, &cert, peers, 60)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Tracker started, listening for requests…")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// catch Ctrl+C
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		log.Println("Shutting down...")
		m.Close()
		cancel()
	}()

	pubKey := priv.Public().(ed25519.PublicKey)
	// start background tasks
	go gcRecent()
	for _, pt := range peerTrackers {
		go runSyncPeer(ctx, pt, pubKey, m.GetTransport())
	}

	// accept loop that respects context
	for {
		select {
		case <-ctx.Done():
			_ = m.Close()
			log.Println("Tracker stopped")
			return
		default:
		}
		conn, err := m.Accept()
		if err != nil {
			continue // listener closed by context
		}
		// distinguish client vs sync connection by first byte
		go func(c *yggquic.Conn) {
			defer c.Close()
			// read 1-byte discriminator
			var disc [1]byte
			if _, err := io.ReadFull(c.Stream, disc[:]); err != nil {
				return
			}
			switch disc[0] {
			case protoSync:
				var callerPub [32]byte
				if _, err := io.ReadFull(c.Stream, callerPub[:]); err != nil {
					return
				}
				// prevent duplicate in the opposite direction
				if alreadyConnected(callerPub) {
					return // silently drop redundant connection
				}
				log.Printf("Got sync connection from %x…", callerPub[:6])
				markConnected(callerPub)
				defer markDisconnected(callerPub)
				runSyncConnection(ctx, c.Stream, callerPub)
			case protoClient:
				handle(ctx, c)
			default:
				return // unknown protocol
			}
		}(conn)
	}
}

// loadOrGenKey returns a private key from file or creates + stores a new one.
func loadOrGenKey() ed25519.PrivateKey {
	if b, err := os.ReadFile(keyFile); err == nil && len(b) == ed25519.PrivateKeySize {
		priv := ed25519.PrivateKey(b)
		log.Printf("Loaded tracker key from %s - private: %x… public : %x\n",
			keyFile, priv[:4], priv.Public())
		return priv
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyFile, priv, 0600); err != nil {
		log.Fatal(err)
	}
	log.Printf("Generated new tracker key (saved to %s) - private: %x… public : %x\n",
		keyFile, priv[:4], priv.Public())
	return priv
}

func createSelfSignedCert(pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, template, template, pub, priv)
}

func handle(ctx context.Context, conn *yggquic.Conn) {
	defer conn.Stream.Close()
	//log.Printf("Handling request…")

	var hdr [38]byte // version(1) + nonce(4) + cmd(1) + userPub(32)
	if _, err := io.ReadFull(conn.Stream, hdr[:]); err != nil {
		return
	}
	if hdr[0] != version {
		return
	}
	nonce := binary.BigEndian.Uint32(hdr[1:5])
	cmd := hdr[5]
	userPub := ([32]byte)(hdr[6:])

	switch cmd {
	case cmdGetAddrs:
		getAddrs(conn, nonce, userPub)
	case cmdAnnounce:
		announce(conn, nonce, userPub)
	default:
	}
	time.Sleep(3 * time.Second)
}

func announce(conn *yggquic.Conn, nonce uint32, userPub [32]byte) {
	//log.Printf("Handling announce request…")
	var body [37]byte // priority(1)+clientID(4)+addrPub(32)+sig(64)  -- read below
	if _, err := io.ReadFull(conn.Stream, body[:37]); err != nil {
		return
	}
	priority := body[0]
	clientID := binary.BigEndian.Uint32(body[1:5])
	addrPub := ([32]byte)(body[5:37])
	var signature [64]byte
	if _, err := io.ReadFull(conn.Stream, signature[:64]); err != nil {
		return
	}
	log.Printf("Got addr: %x… from user: %x…", addrPub[:4], userPub[:4])

	// verify signature
	if !ed25519.Verify(userPub[:], addrPub[:], signature[:]) {
		log.Printf("Wrong signature")
		//conn.Close()
		return
	}

	recordsMu.Lock()

	prevTtl := 2
	for _, r := range records[userPub] {
		if r.ClientID == clientID && r.NodePub == addrPub {
			if r.PrevTtl > 0 {
				prevTtl = r.PrevTtl
			}
		}
	}
	//log.Printf("Prev ttl: %d", prevTtl)
	newTtl := min(prevTtl*2, 16)

	// insert the new one to be the first
	newRecord := record{
		NodePub:   addrPub,
		Signature: signature,
		Priority:  priority,
		ClientID:  clientID,
		Expires:   time.Now().Add(time.Duration(newTtl+1) * time.Minute),
		PrevTtl:   newTtl,
	}

	// keep the slice without the old record (if any)
	oldRecs := records[userPub]
	newRecs := oldRecs[:0] // reuse backing array
	newRecs = append(newRecs, newRecord)
	for _, r := range oldRecs {
		if r.ClientID != clientID {
			newRecs = append(newRecs, r)
		}
	}

	records[userPub] = newRecs
	recordsMu.Unlock()

	// ACK
	resp := make([]byte, 13)
	binary.BigEndian.PutUint32(resp, nonce)
	resp[4] = cmdAnnounce
	binary.BigEndian.PutUint64(resp[5:], uint64(time.Duration(newTtl)*time.Minute/time.Second))
	_, err := conn.Stream.Write(resp)
	if err != nil {
		log.Printf("Write error: %v", err)
		return
	}

	// push new data to fellow trackers
	select {
	case syncChan <- syncItem{
		key:  userPub,
		data: newRecord,
		ttl:  time.Now().Add(time.Duration(newTtl) * time.Minute),
		hop:  maxHopCount,
	}:
	default:
	}
	markRecent(userPub)
	//log.Printf("Sent announce response…")
}

func getAddrs(conn *yggquic.Conn, nonce uint32, userPub [32]byte) {
	recordsMu.RLock()
	recs := records[userPub]
	recordsMu.RUnlock()
	log.Printf("Search for %x…", userPub[:min(2, len(userPub))])

	buf := make([]byte, 9+len(recs)*(32+64+1+4+8)+8) // header + each record + ttl
	off := 0
	buf[off] = byte(nonce >> 24)
	buf[off+1] = byte(nonce >> 16)
	buf[off+2] = byte(nonce >> 8)
	buf[off+3] = byte(nonce)
	off += 4
	buf[off] = cmdGetAddrs
	off++
	buf[off] = byte(len(recs))
	off++

	now := time.Now()
	for _, r := range recs {
		if now.After(r.Expires) {
			buf[5] = buf[5] - 1
			continue // skip expired
		}
		copy(buf[off:], r.NodePub[:])
		off += 32
		copy(buf[off:], r.Signature[:])
		off += 64
		buf[off] = r.Priority
		off++
		binary.BigEndian.PutUint32(buf[off:], r.ClientID)
		off += 4
		binary.BigEndian.PutUint64(buf[off:], uint64(r.Expires.Sub(now)/time.Millisecond))
		off += 8
	}

	if _, err := conn.Stream.Write(buf[:off]); err != nil {
		log.Println("Write:", err)
	}
}

// one goroutine per peer: duplex read+write, no blocking
func runSyncPeer(ctx context.Context, peerHex string, pubKey ed25519.PublicKey, m *yggquic.YggdrasilTransport) {
	backoff := 30 * time.Second

	peerPubBytes, _ := hex.DecodeString(peerHex)
	var peerPub [32]byte
	copy(peerPub[:], peerPubBytes)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if alreadyConnected(peerPub) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}

		conn, err := m.DialContext(ctx, "yggdrasil", peerHex)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		// handshake
		if _, err := conn.Write([]byte{protoSync}); err != nil {
			log.Printf("sync: write protoSync failed: %v", err)
			conn.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		if _, err := conn.Write(pubKey); err != nil {
			log.Printf("sync: write pubKey failed: %v", err)
			conn.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		markConnected(peerPub)
		log.Printf("sync-duplex: connected to %s…", peerHex[:8])

		// ---- main loop ----
		runSyncConnection(ctx, conn, peerPub)

		markDisconnected(peerPub)
		conn.Close()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

func runSyncConnection(ctx context.Context, conn net.Conn, peerPub [32]byte) {
	st := conn
	// make reads non-blocking
	_ = st.SetReadDeadline(time.Time{}) // clear any previous timeout
	readBuf := make([]byte, 1+32)       // cmd+key header
	t, _ := rand.Int(rand.Reader, big.NewInt(16))
	ticker := time.NewTicker((15 + time.Duration(t.Int64())) * time.Second)
	defer ticker.Stop()
	lastPingTime := time.Now()

	for {
		needBreak := false
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			//log.Printf("Sending ping")
			_ = st.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			_, err := st.Write([]byte{cmdSyncPing})
			if err != nil {
				log.Printf("Can't write ping")
				needBreak = true
			}
		default:
			if time.Now().After(lastPingTime.Add(30 * time.Second)) {
				log.Printf("Sync connection timed out")
				needBreak = true
			}
		}

		if needBreak {
			break
		}

		//log.Printf("Reading command")
		// ---------- 1. try to read a command (non-blocking) ----------
		_ = st.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err := io.ReadFull(st, readBuf[:1]) // 1-byte command
		//log.Printf("Read command %d bytes: %v", n, err)
		if err == nil && n > 0 {
			cmd := readBuf[0]
			_ = st.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) // short timeout for payload
			switch cmd {
			case cmdSyncData:
				//log.Printf("Getting record")
				var hop [1]byte
				if _, err := io.ReadFull(st, hop[:]); err != nil {
					break
				}
				if hop[0] == 0 {
					break
				}
				var key [32]byte
				if _, err := io.ReadFull(st, key[:]); err != nil {
					break
				}

				// read data
				recordsMu.Lock()
				recs, exists := records[key]
				var r record
				io.ReadFull(st, r.NodePub[:])
				io.ReadFull(st, r.Signature[:])
				io.ReadFull(st, []byte{r.Priority})
				var tmp [4]byte
				io.ReadFull(st, tmp[:])
				r.ClientID = binary.BigEndian.Uint32(tmp[:])
				io.ReadFull(st, tmp[:])
				ttlSec := binary.BigEndian.Uint32(tmp[:])
				r.Expires = time.Now().Add(time.Duration(ttlSec) * time.Second)
				io.ReadFull(st, tmp[:])
				r.PrevTtl = int(binary.BigEndian.Uint32(tmp[:]))

				// verify signature
				if !ed25519.Verify(key[:], r.NodePub[:], r.Signature[:]) {
					log.Printf("Wrong signature")
					return
				}

				log.Printf("Synced addr: %x… from user: %x…", r.NodePub[:4], key[:4])

				if exists {
					recs = append(recs[:0], append([]record{r}, recs[1:]...)...)
				} else {
					recs = append(recs, r)
				}
				records[key] = recs
				recordsMu.Unlock()

				// forward with decremented hop
				if hop[0] > 1 && !haveRecent(key) {
					select {
					case syncChan <- syncItem{key: key, data: r, ttl: r.Expires, hop: int(hop[0]) - 1}:
					default:
					}
				}
				markRecent(key)
			case cmdSyncPing:
				//log.Printf("Got ping")
				lastPingTime = time.Now()
			default:
				return // unknown cmd → drop connection
			}
		} else if err != nil {
			if err.Error() == "no recent network activity" {
				log.Printf("Peer disconnected")
				break
			}
			if err.Error() != "deadline exceeded" {
				// EOF / reset / any other permanent error → leave
				log.Printf("peer %x… gone: %v", peerPub[:6], err)
				break
			}
		}

		// ---------- 2. check if we have something to push ----------
		select {
		case <-ctx.Done():
			return
		case item := <-syncChan:
			if item.hop <= 0 {
				continue
			}
			// push without asking
			//log.Printf("Sending record")
			_ = st.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			st.Write([]byte{cmdSyncData})
			st.Write([]byte{byte(item.hop)})

			st.Write(item.key[:])
			st.Write(item.data.NodePub[:])
			st.Write(item.data.Signature[:])
			st.Write([]byte{item.data.Priority})
			var tmp [4]byte
			binary.BigEndian.PutUint32(tmp[:], item.data.ClientID)
			st.Write(tmp[:])
			ttl := uint32(time.Until(item.data.Expires).Seconds())
			binary.BigEndian.PutUint32(tmp[:], ttl)
			st.Write(tmp[:])
			binary.BigEndian.PutUint32(tmp[:], uint32(item.data.PrevTtl))
			st.Write(tmp[:])
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// call whenever WE change a key (used both for loop-prevention and for answering "have" queries)
func markRecent(key [32]byte) {
	recentMu.Lock()
	recentUpdate[key] = time.Now()
	recentMu.Unlock()
}

// called by remote: “do you have recent data for key?”
func haveRecent(key [32]byte) bool {
	recentMu.RLock()
	t, ok := recentUpdate[key]
	recentMu.RUnlock()
	return ok && time.Since(t) < 10*time.Second
}

// garbage collect very old entries once in a while
func gcRecent() {
	for {
		time.Sleep(11 * time.Second)
		recentMu.Lock()
		for k, t := range recentUpdate {
			if time.Since(t) > 11*time.Second {
				delete(recentUpdate, k)
			}
		}
		recentMu.Unlock()
	}
}

func alreadyConnected(pub [32]byte) bool {
	connectedMu.Lock()
	_, ok := connected[pub]
	connectedMu.Unlock()
	return ok
}

func markConnected(pub [32]byte) {
	connectedMu.Lock()
	connected[pub] = struct{}{}
	connectedMu.Unlock()
}

func markDisconnected(pub [32]byte) {
	connectedMu.Lock()
	delete(connected, pub)
	connectedMu.Unlock()
}

func saveGob(path string, data interface{}) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		log.Fatal("encode:", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		log.Fatal("write:", err)
	}
}

func loadGob(path string, data interface{}) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	} // first run – nothing to load
	if err != nil {
		log.Fatal("read:", err)
	}
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(data); err != nil {
		log.Fatal("decode:", err)
	}
}
