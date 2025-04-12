package client

import (
	"fmt"
	"net"
	"time"

	"github.com/ramiartas0/hyperdtp/packet"
)

type Client struct {
	ServerAddr *net.UDPAddr
	Conn       *net.UDPConn
	Crypto     *packet.Crypto
	SessionID  string
	Pending    map[string]*pendingPacket
	PendingMu  sync.Mutex
}

type pendingPacket struct {
	packet    *packet.Packet
	sentTime  time.Time
	attempts  int
	onAck     func(*packet.Packet)
	onTimeout func()
}

func New(serverAddr string, sharedKey string) (*Client, error) {
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("sunucu adresi çözülemedi: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("bağlantı kurulamadı: %v", err)
	}

	return &Client{
		ServerAddr: addr,
		Conn:       conn,
		Crypto:     packet.NewCrypto(sharedKey),
		Pending:    make(map[string]*pendingPacket),
	}, nil
}

func (c *Client) Connect() error {
	// El sıkışma paketi gönder
	resp, err := c.SendAndWait(packet.Handshake, map[string]any{
		"client": "hyperdtp-go",
	}, 5*time.Second)

	if err != nil {
		return fmt.Errorf("bağlantı kurulamadı: %v", err)
	}

	c.SessionID = resp.SessionID
	return nil
}

func (c *Client) Send(packetType string, payload map[string]any) (string, error) {
	p := packet.New(packetType, payload, c.SessionID)
	data, err := c.Crypto.Encrypt(p)
	if err != nil {
		return "", fmt.Errorf("paket şifrelenemedi: %v", err)
	}

	if _, err := c.Conn.Write(data); err != nil {
		return "", fmt.Errorf("paket gönderilemedi: %v", err)
	}

	// Bekleyen paketlere ekle
	c.PendingMu.Lock()
	c.Pending[p.ID] = &pendingPacket{
		packet:   p,
		sentTime: time.Now(),
		attempts: 1,
	}
	c.PendingMu.Unlock()

	return p.ID, nil
}

func (c *Client) SendAndWait(packetType string, payload map[string]any, timeout time.Duration) (*packet.Packet, error) {
	ackChan := make(chan *packet.Packet, 1)
	errChan := make(chan error, 1)

	// ACK callback'i
	onAck := func(ack *packet.Packet) {
		ackChan <- ack
	}

	// Timeout callback'i
	onTimeout := func() {
		errChan <- fmt.Errorf("zaman aşımı")
	}

	p := packet.New(packetType, payload, c.SessionID)
	data, err := c.Crypto.Encrypt(p)
	if err != nil {
		return nil, fmt.Errorf("paket şifrelenemedi: %v", err)
	}

	// Bekleyen paketlere ekle
	c.PendingMu.Lock()
	c.Pending[p.ID] = &pendingPacket{
		packet:    p,
		sentTime:  time.Now(),
		attempts:  1,
		onAck:     onAck,
		onTimeout: onTimeout,
	}
	c.PendingMu.Unlock()

	// Gönder
	if _, err := c.Conn.Write(data); err != nil {
		return nil, fmt.Errorf("paket gönderilemedi: %v", err)
	}

	// Yanıt bekle
	select {
	case resp := <-ackChan:
		return resp, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("zaman aşımı")
	}
}

func (c *Client) StartReceiver() {
	buf := make([]byte, 4096)
	for {
		n, err := c.Conn.Read(buf)
		if err != nil {
			fmt.Printf("Okuma hatası: %v\n", err)
			continue
		}

		p, err := c.Crypto.Decrypt(buf[:n])
		if err != nil {
			fmt.Printf("Paket çözme hatası: %v\n", err)
			continue
		}

		// ACK ise bekleyen paketleri işle
		if p.Type == packet.Ack {
			c.handleAck(p)
		} else {
			// Diğer paket türleri
			fmt.Printf("Alınan paket: %v\n", p)
		}
	}
}

func (c *Client) handleAck(ack *packet.Packet) {
	originalID, ok := ack.Payload["original_id"].(string)
	if !ok {
		fmt.Println("Geçersiz ACK paketi")
		return
	}

	c.PendingMu.Lock()
	defer c.PendingMu.Unlock()

	if pending, exists := c.Pending[originalID]; exists {
		if pending.onAck != nil {
			pending.onAck(ack)
		}
		delete(c.Pending, originalID)
	}
}

func (c *Client) ResendWorker() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.PendingMu.Lock()
		now := time.Now()
		for id, pending := range c.Pending {
			if now.Sub(pending.sentTime) > 2*time.Second && pending.attempts < 3 {
				// Yeniden gönder
				data, err := c.Crypto.Encrypt(pending.packet)
				if err != nil {
					fmt.Printf("Yeniden gönderme hatası: %v\n", err)
					continue
				}

				if _, err := c.Conn.Write(data); err != nil {
					fmt.Printf("Yeniden gönderme hatası: %v\n", err)
					continue
				}

				pending.sentTime = now
				pending.attempts++
				fmt.Printf("Paket yeniden gönderildi: %s (Deneme %d)\n", id, pending.attempts)
			} else if pending.attempts >= 3 && pending.onTimeout != nil {
				// Maksimum deneme sayısı aşıldı
				pending.onTimeout()
				delete(c.Pending, id)
			}
		}
		c.PendingMu.Unlock()
	}
}

func (c *Client) Close() error {
	return c.Conn.Close()
}
