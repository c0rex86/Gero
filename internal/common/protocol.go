package common

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const (
	TypeHandshake       = 1
	TypeData            = 2
	TypeControl         = 3
	TypeUDPData         = 4
	TypeUDPBindRequest  = 5
	TypeUDPBindResponse = 6
)

const (
	MaxPacketSize = 65536
	UDPTimeout    = 30 * time.Second
)

type Header struct {
	Type       byte
	PayloadLen uint32
}

type UDPBindRequest struct {
	Port uint16
}

type UDPBindResponse struct {
	Success bool
	Port    uint16
}

type UDPPacket struct {
	SourceIP   net.IP
	SourcePort uint16
	DestIP     net.IP
	DestPort   uint16
	Data       []byte
}

var udpMutex sync.Mutex
var udpConnections = make(map[string]*net.UDPConn)

func WriteHeader(conn net.Conn, header Header) error {
	buf := make([]byte, 5)
	buf[0] = header.Type
	binary.BigEndian.PutUint32(buf[1:], header.PayloadLen)
	_, err := conn.Write(buf)
	return err
}

func ReadHeader(conn net.Conn) (Header, error) {
	buf := make([]byte, 5)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return Header{}, err
	}

	header := Header{
		Type:       buf[0],
		PayloadLen: binary.BigEndian.Uint32(buf[1:]),
	}

	return header, nil
}

type Handshake struct {
	Key string
}

func WriteHandshake(conn net.Conn, handshake Handshake) error {
	keyBytes := []byte(handshake.Key)
	err := WriteHeader(conn, Header{
		Type:       TypeHandshake,
		PayloadLen: uint32(len(keyBytes)),
	})
	if err != nil {
		return err
	}

	_, err = conn.Write(keyBytes)
	return err
}

func ReadHandshake(conn net.Conn, header Header) (Handshake, error) {
	buf := make([]byte, header.PayloadLen)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return Handshake{}, err
	}

	return Handshake{
		Key: string(buf),
	}, nil
}

func Copy(dst, src net.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return err
		}

		err = WriteHeader(dst, Header{
			Type:       TypeData,
			PayloadLen: uint32(n),
		})
		if err != nil {
			return err
		}

		_, err = dst.Write(buf[:n])
		if err != nil {
			return err
		}
	}
}

func WriteUDPBindRequest(conn net.Conn, port uint16) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)

	err := WriteHeader(conn, Header{
		Type:       TypeUDPBindRequest,
		PayloadLen: 2,
	})
	if err != nil {
		return err
	}

	_, err = conn.Write(buf)
	return err
}

func ReadUDPBindRequest(conn net.Conn, header Header) (UDPBindRequest, error) {
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return UDPBindRequest{}, err
	}

	return UDPBindRequest{
		Port: binary.BigEndian.Uint16(buf),
	}, nil
}

func WriteUDPBindResponse(conn net.Conn, response UDPBindResponse) error {
	buf := make([]byte, 3)
	if response.Success {
		buf[0] = 1
	} else {
		buf[0] = 0
	}
	binary.BigEndian.PutUint16(buf[1:], response.Port)

	err := WriteHeader(conn, Header{
		Type:       TypeUDPBindResponse,
		PayloadLen: 3,
	})
	if err != nil {
		return err
	}

	_, err = conn.Write(buf)
	return err
}

func ReadUDPBindResponse(conn net.Conn, header Header) (UDPBindResponse, error) {
	buf := make([]byte, 3)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return UDPBindResponse{}, err
	}

	return UDPBindResponse{
		Success: buf[0] == 1,
		Port:    binary.BigEndian.Uint16(buf[1:]),
	}, nil
}

func WriteUDPPacket(conn net.Conn, packet UDPPacket) error {
	// Формат: [sourceIP(16)][sourcePort(2)][destIP(16)][destPort(2)][data]
	headerSize := 16 + 2 + 16 + 2
	buf := make([]byte, headerSize+len(packet.Data))

	// Нормализуем IP-адреса до 16 байт (поддержка IPv4 и IPv6)
	sourceIP := packet.SourceIP.To16()
	destIP := packet.DestIP.To16()

	copy(buf[0:16], sourceIP)
	binary.BigEndian.PutUint16(buf[16:18], packet.SourcePort)
	copy(buf[18:34], destIP)
	binary.BigEndian.PutUint16(buf[34:36], packet.DestPort)
	copy(buf[36:], packet.Data)

	err := WriteHeader(conn, Header{
		Type:       TypeUDPData,
		PayloadLen: uint32(len(buf)),
	})
	if err != nil {
		return err
	}

	_, err = conn.Write(buf)
	return err
}

func ReadUDPPacket(conn net.Conn, header Header) (UDPPacket, error) {
	buf := make([]byte, header.PayloadLen)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return UDPPacket{}, err
	}

	// Убедимся, что буфер достаточно большой
	if len(buf) < 36 {
		return UDPPacket{}, io.ErrUnexpectedEOF
	}

	sourceIP := net.IP(buf[0:16])
	sourcePort := binary.BigEndian.Uint16(buf[16:18])
	destIP := net.IP(buf[18:34])
	destPort := binary.BigEndian.Uint16(buf[34:36])
	data := buf[36:]

	return UDPPacket{
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		DestIP:     destIP,
		DestPort:   destPort,
		Data:       data,
	}, nil
}

func RegisterUDPConnection(key string, conn *net.UDPConn) {
	udpMutex.Lock()
	defer udpMutex.Unlock()

	udpConnections[key] = conn
}

func GetUDPConnection(key string) *net.UDPConn {
	udpMutex.Lock()
	defer udpMutex.Unlock()

	return udpConnections[key]
}

func RemoveUDPConnection(key string) {
	udpMutex.Lock()
	defer udpMutex.Unlock()

	delete(udpConnections, key)
}

func MakeUDPConnectionKey(ip net.IP, port uint16) string {
	return ip.String() + ":" + string(rune(port))
}
