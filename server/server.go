package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/yourusername/hyperdtp/packet"
)

type Server struct {
	Addr        string
	Conn        *net.UDPConn
	Crypto      *packet.Crypto
	Sessions    map[string]time.Time
	SessionLock sync.RWMutex
}

func New(addr string, sharedKey string) *Server {
	return &Server{
		Addr:     addr,
		Crypto:   packet.NewCrypto(sharedKey),
		Sessions: make(map[string]time.Time),
	}
}

func (s *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("adres çözülemedi: %v", err)
	}

	s.Conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("sunucu başlatılamadı: %v", err)
	}
	defer s.Conn.Close()

	fmt.Printf("HyperDTP sunucusu %s adresinde çalışıyor\n", s.Addr)

	buf := make([]byte, 4096)
	for {
		n, addr, err := s.Conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Okuma hatası: %v\n", err)
			continue
		}

		go s.handlePacket(buf[:n], addr)
	}
}

func (s *Server) handlePacket(data []byte, addr *net.UDPAddr) {
	p, err := s.Crypto.Decrypt(data)
	if err != nil {
		fmt.Printf("Paket çözme hatası: %v\n", err)
		return
	}

	// Oturum güncelleme
	s.SessionLock.Lock()
	s.Sessions[p.SessionID] = time.Now()
	s.SessionLock.Unlock()

	// ACK gönder
	ack := p.CreateAck()
	ackData, err := s.Crypto.Encrypt(ack)
	if err != nil {
		fmt.Printf("ACK oluşturma hatası: %v\n", err)
		return
	}

	if _, err := s.Conn.WriteToUDP(ackData, addr); err != nil {
		fmt.Printf("ACK gönderme hatası: %v\n", err)
	}

	// Paket türüne göre işlem
	switch p.Type {
	case packet.Handshake:
		s.handleHandshake(p, addr)
	case packet.Data:
		s.handleData(p, addr)
	default:
		fmt.Printf("Bilinmeyen paket türü: %s\n", p.Type)
	}
}

func (s *Server) handleHandshake(p *packet.Packet, addr *net.UDPAddr) {
	fmt.Printf("Yeni bağlantı: %s (Oturum: %s)\n", addr.String(), p.SessionID)
	// Bağlantı yanıtı gönder
	response := packet.New(packet.Handshake, map[string]any{
		"status":  "connected",
		"session": p.SessionID,
	}, p.SessionID)

	responseData, err := s.Crypto.Encrypt(response)
	if err != nil {
		fmt.Printf("Yanıt oluşturma hatası: %v\n", err)
		return
	}

	if _, err := s.Conn.WriteToUDP(responseData, addr); err != nil {
		fmt.Printf("Yanıt gönderme hatası: %v\n", err)
	}
}

func (s *Server) handleData(p *packet.Packet, addr *net.UDPAddr) {
	fmt.Printf("Veri alındı: %v (Oturum: %s)\n", p.Payload, p.SessionID)
	// Veri işleme ve yanıt gönderme
	response := packet.New(packet.Data, map[string]any{
		"status":    "received",
		"packet_id": p.ID,
	}, p.SessionID)

	responseData, err := s.Crypto.Encrypt(response)
	if err != nil {
		fmt.Printf("Yanıt oluşturma hatası: %v\n", err)
		return
	}

	if _, err := s.Conn.WriteToUDP(responseData, addr); err != nil {
		fmt.Printf("Yanıt gönderme hatası: %v\n", err)
	}
}

func (s *Server) CleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.SessionLock.Lock()
		now := time.Now()
		for sessionID, lastSeen := range s.Sessions {
			if now.Sub(lastSeen) > 30*time.Minute {
				delete(s.Sessions, sessionID)
				fmt.Printf("Oturum sonlandırıldı: %s\n", sessionID)
			}
		}
		s.SessionLock.Unlock()
	}
}