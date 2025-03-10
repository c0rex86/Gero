package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/c0rex86/gero/internal/common"
)

var (
	ctx             context.Context
	cancel          context.CancelFunc
	serverConn      net.Conn
	udpProxies      = make(map[uint16]*UDPProxy)
	udpProxiesMutex sync.RWMutex
	reconnectMutex  sync.Mutex
	isReconnecting  bool
)

type UDPProxy struct {
	ServerPort  uint16
	LocalPort   uint16
	UDPListener *net.UDPConn
	ClientAddrs map[string]*net.UDPAddr
	AddrMutex   sync.RWMutex
	Closed      bool
}

func Init() error {
	err := common.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	return nil
}

func Shutdown() {
	if cancel != nil {
		cancel()
	}

	if serverConn != nil {
		serverConn.Close()
	}

	udpProxiesMutex.Lock()
	for _, proxy := range udpProxies {
		if proxy.UDPListener != nil {
			proxy.UDPListener.Close()
		}
	}
	udpProxiesMutex.Unlock()
}

func Start(serverAddr string, serverPort int, key string) {
	if err := Init(); err != nil {
		common.ErrorLogger.Printf("Error initializing client: %v", err)
		os.Exit(1)
	}

	if key == "" {
		key = common.GetSecretKey()
	}

	if common.RunAsDaemon() {
		runClient(serverAddr, serverPort, key)
	} else {
		common.InfoLogger.Printf("Starting Gero client, connecting to %s port %d", serverAddr, serverPort)
		runClient(serverAddr, serverPort, key)
	}
}

func StartDaemon(serverAddr string, serverPort int, key string) {
	if key == "" {
		key = common.GetSecretKey()
	}

	args := []string{"client", "--server", serverAddr, "--port", fmt.Sprintf("%d", serverPort), "--key", key}
	common.StartDaemon(args)
}

func runClient(serverAddr string, serverPort int, key string) {
	var err error

	for {
		err = connectToServer(serverAddr, serverPort, key)
		if err == nil {
			break
		}

		common.ErrorLogger.Printf("Failed to connect to server: %v, retrying in 5 seconds", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			continue
		}
	}

	common.InfoLogger.Printf("Connection established to %s", serverConn.RemoteAddr())

	go healthCheck()
	go startLocalProxyServer()

	handleServerMessages()

	common.InfoLogger.Printf("Connection to server closed")
	Shutdown()
}

func connectToServer(serverAddr string, serverPort int, key string) error {
	reconnectMutex.Lock()
	defer reconnectMutex.Unlock()

	if isReconnecting {
		return fmt.Errorf("reconnection already in progress")
	}

	isReconnecting = true
	defer func() { isReconnecting = false }()

	if serverConn != nil {
		serverConn.Close()
		serverConn = nil
	}

	// Установка соединения с таймаутом
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", serverAddr, serverPort))
	if err != nil {
		return fmt.Errorf("dial error: %w", err)
	}

	// Отправка handshake с таймаутом
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	err = common.WriteHandshake(conn, common.Handshake{
		Key: key,
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake error: %w", err)
	}

	conn.SetDeadline(time.Time{}) // Снимаем дедлайн после успешной авторизации
	serverConn = conn

	// Пересоздаем все UDP-прокси после переподключения
	udpProxiesMutex.RLock()
	proxiesToRebind := make(map[uint16]uint16)
	for serverPort, proxy := range udpProxies {
		proxiesToRebind[serverPort] = proxy.LocalPort
		proxy.Closed = true
		if proxy.UDPListener != nil {
			proxy.UDPListener.Close()
		}
	}
	udpProxiesMutex.RUnlock()

	udpProxiesMutex.Lock()
	udpProxies = make(map[uint16]*UDPProxy)
	udpProxiesMutex.Unlock()

	// Пересоздаем UDP привязки
	for serverPort, localPort := range proxiesToRebind {
		go createUDPProxy(serverPort, localPort)
	}

	return nil
}

func healthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if serverConn == nil {
				continue
			}

			udpProxiesMutex.RLock()
			udpCount := len(udpProxies)
			udpProxiesMutex.RUnlock()

			common.DebugLogger.Printf("Health check: connected to %s, %d UDP proxies", serverConn.RemoteAddr(), udpCount)
		}
	}
}

func handleServerMessages() {
	for {
		if serverConn == nil {
			time.Sleep(time.Second)
			continue
		}

		header, err := common.ReadHeader(serverConn)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				common.ErrorLogger.Printf("Error reading header from server: %v", err)
			}

			// Попытка переподключения
			if err := reconnectToServer(); err != nil {
				common.ErrorLogger.Printf("Failed to reconnect: %v", err)
				return
			}
			continue
		}

		switch header.Type {
		case common.TypeData:
			data := make([]byte, header.PayloadLen)
			_, err = io.ReadFull(serverConn, data)
			if err != nil {
				common.ErrorLogger.Printf("Error reading data from server: %v", err)
				return
			}

			handleDataFromServer(data)

		case common.TypeUDPBindResponse:
			response, err := common.ReadUDPBindResponse(serverConn, header)
			if err != nil {
				common.ErrorLogger.Printf("Error reading UDP bind response: %v", err)
				continue
			}
			handleUDPBindResponse(response)

		case common.TypeUDPData:
			packet, err := common.ReadUDPPacket(serverConn, header)
			if err != nil {
				common.ErrorLogger.Printf("Error reading UDP packet: %v", err)
				continue
			}
			handleUDPPacket(packet)

		case common.TypeControl:
			common.InfoLogger.Printf("Received control message")

		default:
			common.ErrorLogger.Printf("Unexpected message type: %d", header.Type)
		}
	}
}

func reconnectToServer() error {
	if isReconnecting {
		common.InfoLogger.Printf("Reconnection already in progress, waiting...")
		time.Sleep(time.Second * 5)
		return nil
	}

	common.InfoLogger.Printf("Connection lost, attempting to reconnect...")

	for i := 0; i < 5; i++ {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled")
		default:
			// Пытаемся переподключиться с кэшированными данными
			serverAddr := common.GetDefaultServer()
			serverPort := common.GetDefaultPort()
			key := common.GetSecretKey()

			err := connectToServer(serverAddr, serverPort, key)
			if err == nil {
				common.InfoLogger.Printf("Successfully reconnected to server")
				return nil
			}

			common.ErrorLogger.Printf("Reconnection attempt %d failed: %v", i+1, err)
			time.Sleep(time.Second * time.Duration(2<<uint(i))) // Экспоненциальная задержка
		}
	}

	return fmt.Errorf("failed to reconnect after multiple attempts")
}

func createUDPProxy(serverPort uint16, localPort uint16) {
	common.InfoLogger.Printf("Creating UDP proxy for server port %d on local port %d", serverPort, localPort)

	// Запрос на создание UDP-привязки на сервере
	err := common.WriteUDPBindRequest(serverConn, serverPort)
	if err != nil {
		common.ErrorLogger.Printf("Failed to send UDP bind request: %v", err)
		return
	}

	// Создание локального UDP-слушателя
	var udpConn *net.UDPConn
	var localUDPPort uint16

	if localPort > 0 {
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(localPort),
		}
		udpConn, err = net.ListenUDP("udp", addr)
		if err != nil {
			common.ErrorLogger.Printf("Failed to bind local UDP port %d: %v", localPort, err)
			return
		}
		localUDPPort = localPort
	} else {
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 0, // Автоматический выбор порта
		}
		udpConn, err = net.ListenUDP("udp", addr)
		if err != nil {
			common.ErrorLogger.Printf("Failed to bind local UDP port: %v", err)
			return
		}
		localUDPPort = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	}

	// Создание и регистрация прокси
	proxy := &UDPProxy{
		ServerPort:  serverPort,
		LocalPort:   localUDPPort,
		UDPListener: udpConn,
		ClientAddrs: make(map[string]*net.UDPAddr),
		AddrMutex:   sync.RWMutex{},
	}

	udpProxiesMutex.Lock()
	udpProxies[serverPort] = proxy
	udpProxiesMutex.Unlock()

	go handleUDPProxy(proxy)
}

func handleUDPBindResponse(response common.UDPBindResponse) {
	if !response.Success {
		common.ErrorLogger.Printf("Server rejected UDP bind request")
		return
	}

	common.InfoLogger.Printf("UDP bind successful on server port %d", response.Port)

	// Проверяем, есть ли уже прокси для этого порта
	udpProxiesMutex.RLock()
	_, exists := udpProxies[response.Port]
	udpProxiesMutex.RUnlock()

	if !exists {
		// Создаем новый прокси для автоматически назначенного порта
		go createUDPProxy(response.Port, 0)
	}
}

func handleUDPProxy(proxy *UDPProxy) {
	defer func() {
		if proxy.UDPListener != nil && !proxy.Closed {
			proxy.UDPListener.Close()
		}

		udpProxiesMutex.Lock()
		delete(udpProxies, proxy.ServerPort)
		udpProxiesMutex.Unlock()
	}()

	buffer := make([]byte, common.MaxPacketSize)

	common.InfoLogger.Printf("UDP proxy listening on 127.0.0.1:%d for server port %d", proxy.LocalPort, proxy.ServerPort)

	for {
		if proxy.Closed {
			return
		}

		proxy.UDPListener.SetReadDeadline(time.Now().Add(common.UDPTimeout))
		n, addr, err := proxy.UDPListener.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			common.ErrorLogger.Printf("Error reading from UDP listener: %v", err)
			return
		}

		// Кэшируем адрес клиента для обратных пакетов
		addrStr := addr.String()
		proxy.AddrMutex.Lock()
		proxy.ClientAddrs[addrStr] = addr
		proxy.AddrMutex.Unlock()

		// Создаем пакет для отправки на сервер
		packet := common.UDPPacket{
			SourceIP:   net.ParseIP("127.0.0.1"),
			SourcePort: proxy.LocalPort,
			DestIP:     net.ParseIP("0.0.0.0"),
			DestPort:   proxy.ServerPort,
			Data:       buffer[:n],
		}

		// Отправляем на сервер
		if serverConn != nil {
			err = common.WriteUDPPacket(serverConn, packet)
			if err != nil {
				common.ErrorLogger.Printf("Error sending UDP packet to server: %v", err)
				if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {
					// Потеря соединения, попытка переподключения
					go reconnectToServer()
				}
			}
		}
	}
}

func handleUDPPacket(packet common.UDPPacket) {
	serverPort := packet.SourcePort

	udpProxiesMutex.RLock()
	proxy, exists := udpProxies[serverPort]
	udpProxiesMutex.RUnlock()

	if !exists || proxy.Closed {
		common.ErrorLogger.Printf("Received UDP packet for non-existent proxy (server port: %d)", serverPort)
		return
	}

	// Определяем клиента для отправки пакета
	var clientAddr *net.UDPAddr

	// Если есть конкретный получатель в пакете
	if packet.DestPort > 0 {
		destAddrStr := fmt.Sprintf("%s:%d", packet.DestIP.String(), packet.DestPort)
		proxy.AddrMutex.RLock()
		addr, ok := proxy.ClientAddrs[destAddrStr]
		proxy.AddrMutex.RUnlock()

		if ok {
			clientAddr = addr
		}
	}

	// Если получатель не определен, просто используем первый активный адрес
	if clientAddr == nil && len(proxy.ClientAddrs) > 0 {
		proxy.AddrMutex.RLock()
		for _, addr := range proxy.ClientAddrs {
			clientAddr = addr
			break
		}
		proxy.AddrMutex.RUnlock()
	}

	if clientAddr == nil {
		common.ErrorLogger.Printf("No client address found for UDP packet from server port %d", serverPort)
		return
	}

	// Отправляем данные клиенту
	_, err := proxy.UDPListener.WriteToUDP(packet.Data, clientAddr)
	if err != nil {
		common.ErrorLogger.Printf("Error forwarding UDP packet to client: %v", err)
	}
}

func handleDataFromServer(data []byte) {
	common.DebugLogger.Printf("Received %d bytes from server", len(data))
}

func startLocalProxyServer() {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		common.ErrorLogger.Printf("Error starting local proxy server: %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	common.InfoLogger.Printf("Local proxy server listening on %s", listener.Addr())
	common.InfoLogger.Printf("You can access the remote network through this proxy")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				common.ErrorLogger.Printf("Error accepting connection: %v", err)
				continue
			}

			go handleLocalConnection(conn)
		}
	}
}

func handleLocalConnection(localConn net.Conn) {
	defer localConn.Close()

	if serverConn == nil {
		common.ErrorLogger.Printf("Cannot handle local connection: no server connection")
		return
	}

	done := make(chan struct{})

	go func() {
		buf := make([]byte, 32*1024)
		for {
			localConn.SetReadDeadline(time.Now().Add(time.Minute))
			n, err := localConn.Read(buf)
			if err != nil {
				if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
					common.ErrorLogger.Printf("Error reading from local connection: %v", err)
				}
				break
			}

			if serverConn == nil {
				common.ErrorLogger.Printf("Server connection lost while handling local connection")
				break
			}

			err = common.WriteHeader(serverConn, common.Header{
				Type:       common.TypeData,
				PayloadLen: uint32(n),
			})
			if err != nil {
				common.ErrorLogger.Printf("Error sending data header to server: %v", err)
				if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {
					// Потеря соединения, запускаем переподключение
					go reconnectToServer()
				}
				break
			}

			_, err = serverConn.Write(buf[:n])
			if err != nil {
				common.ErrorLogger.Printf("Error sending data to server: %v", err)
				if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {
					// Потеря соединения, запускаем переподключение
					go reconnectToServer()
				}
				break
			}
		}
		close(done)
	}()

	<-done
}
