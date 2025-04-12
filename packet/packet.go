package packet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// Paket tipleri
const (
	Handshake = "handshake"
	Data      = "data"
	Ack       = "ack"
	Error     = "error"
)

// Paket yapısı
type Packet struct {
	Type      string         `json:"type"`
	Payload   map[string]any `json:"payload"`
	ID        string         `json:"id"`
	SessionID string         `json:"session_id"`
	Timestamp int64          `json:"timestamp"`
}

// Yeni paket oluşturma
func New(packetType string, payload map[string]any, sessionID string) *Packet {
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	return &Packet{
		Type:      packetType,
		Payload:   payload,
		ID:        uuid.New().String(),
		SessionID: sessionID,
		Timestamp: time.Now().Unix(),
	}
}

// ACK paketi oluşturma
func (p *Packet) CreateAck() *Packet {
	return New(Ack, map[string]any{
		"original_id": p.ID,
		"status":      "received",
	}, p.SessionID)
}

// Şifreleme yapısı
type Crypto struct {
	key []byte
	iv  []byte
}

func NewCrypto(sharedKey string) *Crypto {
	hash := sha256.Sum256([]byte(sharedKey))
	return &Crypto{
		key: hash[:],
		iv:  make([]byte, aes.BlockSize),
	}
}

// Paket şifreleme
func (c *Crypto) Encrypt(p *Packet) ([]byte, error) {
	// IV üret
	if _, err := io.ReadFull(rand.Reader, c.iv); err != nil {
		return nil, err
	}

	// JSON'a çevir
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	// AES-CBC şifreleme
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	// PKCS7 padding
	padded := pkcs7Pad(data, aes.BlockSize)
	encrypted := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, c.iv)
	mode.CryptBlocks(encrypted, padded)

	// IV + şifrelenmiş veri
	return append(c.iv, encrypted...), nil
}

// Paket çözme
func (c *Crypto) Decrypt(data []byte) (*Packet, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("şifrelenmiş veri çok kısa")
	}

	// IV ve şifrelenmiş veriyi ayır
	iv := data[:aes.BlockSize]
	encrypted := data[aes.BlockSize:]

	// AES-CBC çözme
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	if len(encrypted)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("şifrelenmiş veri boyutu geçersiz")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// PKCS7 unpadding
	unpadded, err := pkcs7Unpad(decrypted)
	if err != nil {
		return nil, err
	}

	// JSON'dan pakete çevir
	var p Packet
	if err := json.Unmarshal(unpadded, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

// PKCS7 padding yardımcı fonksiyonları
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("padding hatası: boş veri")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil, errors.New("padding hatası")
	}
	return data[:len(data)-padding], nil
}
