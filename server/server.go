package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c0rex86/gero/internal/common"
)

var (
	clients      = make(map[string]net.Conn)
	clientsMutex sync.Mutex
	udpProxies   = make(map[string]*UDPProxy)
	udpMutex     sync.Mutex
	tcpProxies   = make(map[string]*TCPProxy)
	tcpMutex     sync.RWMutex
	routes       = make(map[string]string)
	routesMutex  sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	connMutex    sync.Mutex
	activeConns  map[string][]net.Conn = make(map[string][]net.Conn)
	requireTOTP  bool
)

type UDPProxy struct {
	ClientConn     net.Conn
	UDPListener    *net.UDPConn
	LocalPort      int
	RemoteAddrMap  map[string]*net.UDPAddr
	RemoteAddrLock sync.RWMutex
	Closed         bool
}

type TCPProxy struct {
	ClientConn  net.Conn
	LocalPort   int
	TargetHost  string
	TargetPort  int
	Connections map[string]net.Conn
	ConnLock    sync.RWMutex
	Closed      bool
}

type Route struct {
	SourcePort int
	TargetHost string
	TargetPort int
	Protocol   string
}

func Init() error {
	err := common.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	ctx, cancel = context.WithCancel(context.Background())

	// Загрузка маршрутов из конфигурации
	loadRoutes()

	return nil
}

func loadRoutes() {
	// Здесь можно загрузить маршруты из конфигурационного файла
	routesMutex.Lock()
	defer routesMutex.Unlock()

	// Пример стандартных маршрутов
	routes["web"] = "80:80"     // HTTP
	routes["ssh"] = "22:22"     // SSH
	routes["rdp"] = "3389:3389" // RDP
	routes["vnc"] = "5900:5900" // VNC
}

func AddRoute(name, targetHost string, sourcePort, targetPort int, protocol string) {
	routesMutex.Lock()
	defer routesMutex.Unlock()

	routeKey := fmt.Sprintf("%s:%d:%s", targetHost, targetPort, protocol)
	routes[name] = routeKey

	common.InfoLogger.Printf("Added route '%s': %s:%d (%s)", name, targetHost, targetPort, protocol)
}

func GetRoute(name string) (Route, bool) {
	routesMutex.RLock()
	defer routesMutex.RUnlock()

	routeStr, exists := routes[name]
	if !exists {
		return Route{}, false
	}

	parts := strings.Split(routeStr, ":")
	if len(parts) < 3 {
		return Route{}, false
	}

	sourcePort := 0
	targetPort := 0

	fmt.Sscanf(parts[0], "%d", &sourcePort)

	targetHost := parts[1]
	fmt.Sscanf(parts[2], "%d", &targetPort)

	protocol := "tcp"
	if len(parts) > 3 {
		protocol = parts[3]
	}

	return Route{
		SourcePort: sourcePort,
		TargetHost: targetHost,
		TargetPort: targetPort,
		Protocol:   protocol,
	}, true
}

func ListRoutes() []string {
	routesMutex.RLock()
	defer routesMutex.RUnlock()

	result := make([]string, 0, len(routes))
	for name, route := range routes {
		result = append(result, fmt.Sprintf("%s -> %s", name, route))
	}

	return result
}

func Shutdown() {
	if cancel != nil {
		cancel()
	}

	clientsMutex.Lock()
	for _, conn := range clients {
		conn.Close()
	}
	clientsMutex.Unlock()

	udpMutex.Lock()
	for _, proxy := range udpProxies {
		if proxy.UDPListener != nil {
			proxy.UDPListener.Close()
		}
	}
	udpMutex.Unlock()

	tcpMutex.Lock()
	for _, proxy := range tcpProxies {
		for _, conn := range proxy.Connections {
			conn.Close()
		}
	}
	tcpMutex.Unlock()
}

func Start(bindAddr string, port int) {
	if err := Init(); err != nil {
		common.ErrorLogger.Printf("Error initializing server: %v", err)
		os.Exit(1)
	}

	if common.RunAsDaemon() {
		runServer(bindAddr, port)
	} else {
		common.InfoLogger.Printf("Starting Gero server on %s port %d", bindAddr, port)
		runServer(bindAddr, port)
	}
}

func StartDaemon(bindAddr string, port int) {
	args := []string{"server", "--bind", bindAddr, "--port", fmt.Sprintf("%d", port)}
	common.StartDaemon(args)
}

func runServer(bindAddr string, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindAddr, port))
	if err != nil {
		common.ErrorLogger.Printf("Error starting server: %v", err)
		os.Exit(1)
	}
	defer listener.Close()

	common.InfoLogger.Printf("Gero server listening on %s", listener.Addr())

	go healthCheck()
	go startDefaultTCPProxies()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			common.ErrorLogger.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func startDefaultTCPProxies() {
	routesMutex.RLock()
	defer routesMutex.RUnlock()

	for name, routeStr := range routes {
		parts := strings.Split(routeStr, ":")
		if len(parts) < 3 {
			continue
		}

		sourcePort := 0
		targetPort := 0

		fmt.Sscanf(parts[0], "%d", &sourcePort)

		targetHost := parts[1]
		fmt.Sscanf(parts[2], "%d", &targetPort)

		protocol := "tcp"
		if len(parts) > 3 {
			protocol = parts[3]
		}

		if protocol == "tcp" && sourcePort > 0 {
			go startTCPProxy(nil, sourcePort, targetHost, targetPort)
			common.InfoLogger.Printf("Started default TCP proxy for route '%s': %d -> %s:%d",
				name, sourcePort, targetHost, targetPort)
		}
	}
}

func healthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			clientsMutex.Lock()
			activeClientCount := len(clients)
			clientsMutex.Unlock()

			udpMutex.Lock()
			udpCount := len(udpProxies)
			udpMutex.Unlock()

			tcpMutex.Lock()
			tcpCount := len(tcpProxies)
			tcpMutex.Unlock()

			common.DebugLogger.Printf("Health check: %d active clients, %d UDP proxies, %d TCP proxies",
				activeClientCount, udpCount, tcpCount)

			// Проверка подключений клиентов
			clientsMutex.Lock()
			for addr, conn := range clients {
				// Отправляем ping для проверки соединения
				err := common.WriteHeader(conn, common.Header{
					Type:       common.TypeControl,
					PayloadLen: 0,
				})
				if err != nil {
					common.DebugLogger.Printf("Client %s appears to be disconnected: %v", addr, err)
					conn.Close()
					delete(clients, addr)

					// Удаляем связанные UDP-прокси
					udpMutex.Lock()
					if proxy, exists := udpProxies[addr]; exists {
						if proxy.UDPListener != nil {
							proxy.UDPListener.Close()
						}
						proxy.Closed = true
						delete(udpProxies, addr)
					}
					udpMutex.Unlock()

					// Удаляем связанные TCP-прокси
					tcpMutex.Lock()
					if proxy, exists := tcpProxies[addr]; exists {
						for _, conn := range proxy.Connections {
							conn.Close()
						}
						proxy.Closed = true
						delete(tcpProxies, addr)
					}
					tcpMutex.Unlock()
				}
			}
			clientsMutex.Unlock()
		}
	}
}

func handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		clientAddr := conn.RemoteAddr().String()

		clientsMutex.Lock()
		delete(clients, clientAddr)
		clientsMutex.Unlock()

		udpMutex.Lock()
		if proxy, exists := udpProxies[clientAddr]; exists {
			if proxy.UDPListener != nil {
				proxy.UDPListener.Close()
			}
			proxy.Closed = true
			delete(udpProxies, clientAddr)
		}
		udpMutex.Unlock()

		tcpMutex.Lock()
		if proxy, exists := tcpProxies[clientAddr]; exists {
			for _, conn := range proxy.Connections {
				conn.Close()
			}
			proxy.Closed = true
			delete(tcpProxies, clientAddr)
		}
		tcpMutex.Unlock()

		common.InfoLogger.Printf("Client disconnected: %s", clientAddr)
	}()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	header, err := common.ReadHeader(conn)
	if err != nil {
		common.ErrorLogger.Printf("Error reading header: %v", err)
		return
	}

	if header.Type != common.TypeHandshake {
		common.ErrorLogger.Printf("Expected handshake, got type: %d", header.Type)
		return
	}

	handshake, err := common.ReadHandshake(conn, header)
	if err != nil {
		common.ErrorLogger.Printf("Error reading handshake: %v", err)
		return
	}

	conn.SetDeadline(time.Time{}) // Снимаем дедлайн после успешной аутентификации

	if handshake.Key != common.GetSecretKey() {
		common.ErrorLogger.Printf("Invalid key: %s", handshake.Key)
		return
	}

	clientAddr := conn.RemoteAddr().String()

	clientsMutex.Lock()
	clients[clientAddr] = conn
	clientsMutex.Unlock()

	common.InfoLogger.Printf("Client connected: %s", clientAddr)

	go handleLocalNetworkAccess(conn)
	processClientRequests(conn)
}

func processClientRequests(clientConn net.Conn) {
	for {
		header, err := common.ReadHeader(clientConn)
		if err != nil {
			if err != io.EOF {
				common.ErrorLogger.Printf("Error reading header from client: %v", err)
			}
			return
		}

		switch header.Type {
		case common.TypeUDPBindRequest:
			request, err := common.ReadUDPBindRequest(clientConn, header)
			if err != nil {
				common.ErrorLogger.Printf("Error reading UDP bind request: %v", err)
				continue
			}
			handleUDPBindRequest(clientConn, request)

		case common.TypeUDPData:
			packet, err := common.ReadUDPPacket(clientConn, header)
			if err != nil {
				common.ErrorLogger.Printf("Error reading UDP packet: %v", err)
				continue
			}
			handleUDPData(clientConn, packet)

		case common.TypeData:
			data := make([]byte, header.PayloadLen)
			_, err = io.ReadFull(clientConn, data)
			if err != nil {
				common.ErrorLogger.Printf("Error reading data from client: %v", err)
				return
			}

			handleTCPData(clientConn, data)

		case common.TypeControl:
			// Обработка контрольных сообщений
			if header.PayloadLen > 0 {
				controlData := make([]byte, header.PayloadLen)
				_, err = io.ReadFull(clientConn, controlData)
				if err != nil {
					common.ErrorLogger.Printf("Error reading control data: %v", err)
					continue
				}

				// Обработка контрольных команд
				handleControlMessage(clientConn, controlData)
			} else {
				// Это ping, отправляем pong
				err = common.WriteHeader(clientConn, common.Header{
					Type:       common.TypeControl,
					PayloadLen: 0,
				})
				if err != nil {
					common.ErrorLogger.Printf("Error sending pong: %v", err)
					return
				}
			}

		default:
			common.ErrorLogger.Printf("Unexpected message type: %d", header.Type)
		}
	}
}

func handleControlMessage(clientConn net.Conn, data []byte) {
	if len(data) == 0 {
		return
	}

	// Формат сообщений управления: [CommandType][Data...]
	command := data[0]
	payload := data[1:]

	switch command {
	case 1: // CreateTCPProxy
		if len(payload) < 6 {
			common.ErrorLogger.Printf("Invalid TCP proxy creation command")
			return
		}

		sourcePort := int(payload[0])<<8 | int(payload[1])
		targetPort := int(payload[2])<<8 | int(payload[3])
		hostLen := int(payload[4])

		if len(payload) < 5+hostLen {
			common.ErrorLogger.Printf("Invalid target host in TCP proxy creation command")
			return
		}

		targetHost := string(payload[5 : 5+hostLen])
		startTCPProxy(clientConn, sourcePort, targetHost, targetPort)

	case 2: // CloseTCPProxy
		if len(payload) < 2 {
			common.ErrorLogger.Printf("Invalid TCP proxy close command")
			return
		}

		port := int(payload[0])<<8 | int(payload[1])
		closeTCPProxy(clientConn, port)

	default:
		common.ErrorLogger.Printf("Unknown control command: %d", command)
	}
}

func startTCPProxy(clientConn net.Conn, sourcePort int, targetHost string, targetPort int) {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", sourcePort))
	if err != nil {
		common.ErrorLogger.Printf("Error creating TCP proxy listener on port %d: %v", sourcePort, err)

		if clientConn != nil {
			// Сообщаем клиенту об ошибке
			response := []byte{0, 0} // Неудача
			err = common.WriteHeader(clientConn, common.Header{
				Type:       common.TypeControl,
				PayloadLen: uint32(len(response)),
			})
			if err == nil {
				clientConn.Write(response)
			}
		}
		return
	}

	actualPort := listener.Addr().(*net.TCPAddr).Port

	proxy := &TCPProxy{
		ClientConn:  clientConn,
		LocalPort:   actualPort,
		TargetHost:  targetHost,
		TargetPort:  targetPort,
		Connections: make(map[string]net.Conn),
		ConnLock:    sync.RWMutex{},
	}

	if clientConn != nil {
		clientAddr := clientConn.RemoteAddr().String()

		tcpMutex.Lock()
		tcpProxies[clientAddr] = proxy
		tcpMutex.Unlock()

		// Сообщаем клиенту об успехе
		response := []byte{1, byte(actualPort >> 8), byte(actualPort)}
		err = common.WriteHeader(clientConn, common.Header{
			Type:       common.TypeControl,
			PayloadLen: uint32(len(response)),
		})
		if err == nil {
			clientConn.Write(response)
		}
	}

	common.InfoLogger.Printf("Started TCP proxy on port %d, forwarding to %s:%d",
		actualPort, targetHost, targetPort)

	go func() {
		defer listener.Close()

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
					common.ErrorLogger.Printf("Error accepting TCP connection: %v", err)
					continue
				}

				go handleTCPConnection(proxy, conn)
			}
		}
	}()
}

func closeTCPProxy(clientConn net.Conn, port int) {
	clientAddr := clientConn.RemoteAddr().String()

	tcpMutex.Lock()
	defer tcpMutex.Unlock()

	proxy, exists := tcpProxies[clientAddr]
	if !exists || proxy.LocalPort != port {
		common.ErrorLogger.Printf("Attempt to close non-existent TCP proxy on port %d", port)
		return
	}

	for _, conn := range proxy.Connections {
		conn.Close()
	}

	proxy.Closed = true
	delete(tcpProxies, clientAddr)

	common.InfoLogger.Printf("Closed TCP proxy on port %d", port)

	// Отправляем подтверждение клиенту
	response := []byte{1}
	err := common.WriteHeader(clientConn, common.Header{
		Type:       common.TypeControl,
		PayloadLen: uint32(len(response)),
	})
	if err == nil {
		clientConn.Write(response)
	}
}

func handleTCPConnection(proxy *TCPProxy, localConn net.Conn) {
	defer localConn.Close()

	if proxy.Closed {
		return
	}

	remoteAddr := localConn.RemoteAddr().String()

	// Устанавливаем соединение с целевым хостом
	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxy.TargetHost, proxy.TargetPort), 10*time.Second)
	if err != nil {
		common.ErrorLogger.Printf("Error connecting to target %s:%d: %v",
			proxy.TargetHost, proxy.TargetPort, err)
		return
	}
	defer targetConn.Close()

	proxy.ConnLock.Lock()
	proxy.Connections[remoteAddr] = localConn
	proxy.ConnLock.Unlock()

	defer func() {
		proxy.ConnLock.Lock()
		delete(proxy.Connections, remoteAddr)
		proxy.ConnLock.Unlock()
	}()

	// Двунаправленное копирование данных
	done := make(chan bool, 2)

	go func() {
		io.Copy(targetConn, localConn)
		done <- true
	}()

	go func() {
		io.Copy(localConn, targetConn)
		done <- true
	}()

	<-done
}

func handleUDPBindRequest(clientConn net.Conn, request common.UDPBindRequest) {
	clientAddr := clientConn.RemoteAddr().String()
	common.InfoLogger.Printf("UDP bind request from %s for port %d", clientAddr, request.Port)

	var port uint16 = 0
	var udpConn *net.UDPConn
	var err error

	// Пытаемся создать UDP слушатель
	for attempts := 0; attempts < 5; attempts++ {
		var addr *net.UDPAddr
		if request.Port > 0 {
			addr = &net.UDPAddr{
				IP:   net.ParseIP("0.0.0.0"),
				Port: int(request.Port),
			}
		} else {
			addr = &net.UDPAddr{
				IP:   net.ParseIP("0.0.0.0"),
				Port: 0, // Автоматический выбор порта
			}
		}

		udpConn, err = net.ListenUDP("udp", addr)
		if err == nil {
			port = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
			break
		}

		common.ErrorLogger.Printf("Failed to bind UDP port (attempt %d): %v", attempts+1, err)
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		common.ErrorLogger.Printf("Failed to bind UDP port after multiple attempts: %v", err)
		err = common.WriteUDPBindResponse(clientConn, common.UDPBindResponse{
			Success: false,
			Port:    0,
		})
		if err != nil {
			common.ErrorLogger.Printf("Error sending UDP bind failure: %v", err)
		}
		return
	}

	udpProxy := &UDPProxy{
		ClientConn:     clientConn,
		UDPListener:    udpConn,
		LocalPort:      int(port),
		RemoteAddrMap:  make(map[string]*net.UDPAddr),
		RemoteAddrLock: sync.RWMutex{},
	}

	udpMutex.Lock()
	udpProxies[clientAddr] = udpProxy
	udpMutex.Unlock()

	common.InfoLogger.Printf("UDP proxy established for %s on port %d", clientAddr, port)

	err = common.WriteUDPBindResponse(clientConn, common.UDPBindResponse{
		Success: true,
		Port:    port,
	})
	if err != nil {
		common.ErrorLogger.Printf("Error sending UDP bind response: %v", err)
		udpConn.Close()
		return
	}

	go handleUDPListener(udpProxy)
}

func handleUDPListener(proxy *UDPProxy) {
	defer func() {
		if proxy.UDPListener != nil && !proxy.Closed {
			proxy.UDPListener.Close()
		}
	}()

	buffer := make([]byte, common.MaxPacketSize)

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
			common.ErrorLogger.Printf("Error reading from UDP: %v", err)
			return
		}

		addrStr := addr.String()

		proxy.RemoteAddrLock.Lock()
		proxy.RemoteAddrMap[addrStr] = addr
		proxy.RemoteAddrLock.Unlock()

		packet := common.UDPPacket{
			SourceIP:   addr.IP,
			SourcePort: uint16(addr.Port),
			DestIP:     net.ParseIP("127.0.0.1"),
			DestPort:   uint16(proxy.LocalPort),
			Data:       buffer[:n],
		}

		err = common.WriteUDPPacket(proxy.ClientConn, packet)
		if err != nil {
			common.ErrorLogger.Printf("Error sending UDP packet to client: %v", err)
			return
		}
	}
}

func handleUDPData(clientConn net.Conn, packet common.UDPPacket) {
	clientAddr := clientConn.RemoteAddr().String()

	udpMutex.Lock()
	proxy, exists := udpProxies[clientAddr]
	udpMutex.Unlock()

	if !exists || proxy.Closed {
		common.ErrorLogger.Printf("Received UDP data from %s but no active UDP proxy found", clientAddr)
		return
	}

	// Construct destination address
	destAddr := &net.UDPAddr{
		IP:   packet.DestIP,
		Port: int(packet.DestPort),
	}

	_, err := proxy.UDPListener.WriteToUDP(packet.Data, destAddr)
	if err != nil {
		common.ErrorLogger.Printf("Error forwarding UDP packet: %v", err)
	}
}

func handleTCPData(clientConn net.Conn, data []byte) {
	// Теперь эта функция обрабатывает данные, пришедшие от клиента
	// для проксирования в соответствующее TCP-соединение.
	// Формат данных: [connectionID (4 bytes)][data...]
	if len(data) < 4 {
		common.ErrorLogger.Printf("Invalid TCP data format (too short)")
		return
	}

	connectionID := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	payload := data[4:]

	clientAddr := clientConn.RemoteAddr().String()

	tcpMutex.RLock()
	proxy, exists := tcpProxies[clientAddr]
	tcpMutex.RUnlock()

	if !exists || proxy.Closed {
		common.ErrorLogger.Printf("Received TCP data from %s but no active TCP proxy found", clientAddr)
		return
	}

	proxy.ConnLock.RLock()
	conn, exists := proxy.Connections[connectionID]
	proxy.ConnLock.RUnlock()

	if !exists {
		common.ErrorLogger.Printf("Connection ID %s not found", connectionID)
		return
	}

	_, err := conn.Write(payload)
	if err != nil {
		common.ErrorLogger.Printf("Error writing to TCP connection: %v", err)

		// Закрываем соединение если возникла ошибка
		conn.Close()

		proxy.ConnLock.Lock()
		delete(proxy.Connections, connectionID)
		proxy.ConnLock.Unlock()
	}
}

func handleLocalNetworkAccess(clientConn net.Conn) {
	localListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		common.ErrorLogger.Printf("Error creating local listener: %v", err)
		return
	}
	defer localListener.Close()

	common.InfoLogger.Printf("Local service available at: %s", localListener.Addr())

	for {
		select {
		case <-ctx.Done():
			return
		default:
			localListener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			localConn, err := localListener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				common.ErrorLogger.Printf("Error accepting local connection: %v", err)
				continue
			}

			go proxyConnection(localConn, clientConn)
		}
	}
}

func proxyConnection(localConn, clientConn net.Conn) {
	defer localConn.Close()

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

			err = common.WriteHeader(clientConn, common.Header{
				Type:       common.TypeData,
				PayloadLen: uint32(n),
			})
			if err != nil {
				common.ErrorLogger.Printf("Error sending data header to client: %v", err)
				break
			}

			_, err = clientConn.Write(buf[:n])
			if err != nil {
				common.ErrorLogger.Printf("Error sending data to client: %v", err)
				break
			}
		}
		close(done)
	}()

	<-done
}

// StartServer - Запустить сервер с расширенными настройками безопасности
func StartServer(port int, enableIPFilter bool, requireTOTPAuth bool, daemonMode bool) error {
	// Инициализируем конфигурацию
	if err := common.LoadConfig(); err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	// Устанавливаем глобальные настройки
	requireTOTP = requireTOTPAuth

	// Загружаем разрешенные IP-адреса если включена фильтрация
	if enableIPFilter {
		_, err := common.LoadAllowedIPs()
		if err != nil {
			return fmt.Errorf("failed to load allowed IPs: %v", err)
		}
		common.EnableIPFilter(true)
		common.InfoLogger.Println("IP filtering enabled")
	}

	// Загружаем TOTP-секрет если требуется аутентификация
	if requireTOTP {
		if _, err := common.LoadTOTPSecret(); err != nil {
			return fmt.Errorf("failed to load TOTP secret: %v", err)
		}
		common.EnableTOTP(true)
		common.InfoLogger.Println("TOTP authentication enabled")
	}

	// Запускаем сервер
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	common.InfoLogger.Printf("Server started on port %d", port)

	// Если запускаем в режиме демона, то переход в фоновый режим
	if daemonMode {
		if err := daemonize(); err != nil {
			return fmt.Errorf("failed to daemonize: %v", err)
		}
		return nil
	}

	// Обработка сигналов для корректного завершения
	go handleServerSignals()

	// Принимаем соединения в бесконечном цикле
	for {
		conn, err := listener.Accept()
		if err != nil {
			common.ErrorLogger.Printf("Error accepting connection: %v", err)
			continue
		}

		// Получаем IP-адрес клиента
		remoteAddr := conn.RemoteAddr().String()
		clientIP := strings.Split(remoteAddr, ":")[0]

		// Проверяем IP-адрес если включена фильтрация
		if enableIPFilter && !common.IsIPAllowed(clientIP) {
			common.InfoLogger.Printf("Connection from %s rejected (IP not allowed)", clientIP)
			conn.Close()
			continue
		}

		common.InfoLogger.Printf("New connection from %s", remoteAddr)

		// Запускаем обработку соединения в отдельной горутине
		go handleClientConnection(conn)
	}
}

// Функция для перехода в фоновый режим
func daemonize() error {
	// Здесь можно добавить логику для демонизации процесса
	// В простейшем случае - просто отключиться от терминала и продолжить работу
	common.InfoLogger.Println("Server is now running in background mode")
	return nil
}

// Обработка сигналов для корректного завершения
func handleServerSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	common.InfoLogger.Println("Shutting down server...")

	// Закрываем все активные соединения
	connMutex.Lock()
	for _, conns := range activeConns {
		for _, conn := range conns {
			conn.Close()
		}
	}
	connMutex.Unlock()

	// Даём время на закрытие соединений
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

// Обработка входящего соединения
func handleClientConnection(conn net.Conn) {
	defer conn.Close()

	// Установка таймаута на чтение при аутентификации
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Буфер для чтения команды
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		common.ErrorLogger.Printf("Error reading from connection: %v", err)
		return
	}

	// Анализируем полученную команду
	command := string(buffer[:n])
	parts := strings.Split(strings.TrimSpace(command), " ")

	if len(parts) < 2 {
		common.ErrorLogger.Printf("Invalid command format: %s", command)
		fmt.Fprintf(conn, "ERROR: Invalid command format\n")
		return
	}

	// Проверяем ключ авторизации
	secretKey := common.GetSecretKey()
	if parts[0] != secretKey {
		common.ErrorLogger.Printf("Invalid secret key from %s", conn.RemoteAddr().String())
		fmt.Fprintf(conn, "ERROR: Authentication failed\n")
		return
	}

	// Проверяем TOTP если требуется
	if requireTOTP {
		if len(parts) < 3 {
			common.ErrorLogger.Printf("TOTP code required but not provided from %s", conn.RemoteAddr().String())
			fmt.Fprintf(conn, "ERROR: TOTP code required\n")
			return
		}

		totpCode := parts[2]
		if !common.ValidateTOTP(totpCode) {
			common.ErrorLogger.Printf("Invalid TOTP code from %s", conn.RemoteAddr().String())
			fmt.Fprintf(conn, "ERROR: Invalid TOTP code\n")
			return
		}

		common.InfoLogger.Printf("TOTP authentication successful from %s", conn.RemoteAddr().String())

		// Удаляем TOTP-код из команды для дальнейшей обработки
		parts = append(parts[:2], parts[3:]...)
	}

	// Сбрасываем таймаут после аутентификации
	conn.SetReadDeadline(time.Time{})

	// Обрабатываем команду
	switch parts[1] {
	case "connect":
		if len(parts) < 5 {
			fmt.Fprintf(conn, "ERROR: Invalid connect command\n")
			return
		}

		localPort, err := strconv.Atoi(parts[2])
		if err != nil {
			fmt.Fprintf(conn, "ERROR: Invalid local port\n")
			return
		}

		remoteHost := parts[3]
		remotePort, err := strconv.Atoi(parts[4])
		if err != nil {
			fmt.Fprintf(conn, "ERROR: Invalid remote port\n")
			return
		}

		// Проверяем протокол (опционально)
		protocol := "tcp"
		if len(parts) > 5 {
			protocol = parts[5]
		}

		// Запускаем проксирование
		setupAdvancedProxy(conn, localPort, remoteHost, remotePort, protocol)

	default:
		fmt.Fprintf(conn, "ERROR: Unknown command: %s\n", parts[1])
	}
}

// Настройка проксирования
func setupAdvancedProxy(conn net.Conn, localPort int, remoteHost string, remotePort int, protocol string) {
	// Проверяем корректность протокола
	if protocol != "tcp" && protocol != "udp" {
		fmt.Fprintf(conn, "ERROR: Unsupported protocol: %s\n", protocol)
		return
	}

	// Создаем слушателя на локальном порту
	addr := fmt.Sprintf(":%d", localPort)
	var listener net.Listener
	var err error

	listener, err = net.Listen(protocol, addr)
	if err != nil {
		common.ErrorLogger.Printf("Failed to bind to %s: %v", addr, err)
		fmt.Fprintf(conn, "ERROR: Failed to bind to port %d: %v\n", localPort, err)
		return
	}

	// Регистрируем соединение
	connID := fmt.Sprintf("%d-%s-%d", localPort, remoteHost, remotePort)

	// Добавляем соединение в список активных
	connMutex.Lock()
	if _, exists := activeConns[connID]; !exists {
		activeConns[connID] = []net.Conn{conn}
	} else {
		activeConns[connID] = append(activeConns[connID], conn)
	}
	connMutex.Unlock()

	// Уведомляем клиента о успешном подключении
	fmt.Fprintf(conn, "SUCCESS: Proxy established on port %d to %s:%d\n", localPort, remoteHost, remotePort)

	common.InfoLogger.Printf("Proxy established on port %d to %s:%d (%s)", localPort, remoteHost, remotePort, protocol)

	// Обработка входящих соединений
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			common.ErrorLogger.Printf("Error accepting connection on proxy: %v", err)
			break
		}

		common.InfoLogger.Printf("New proxied connection from %s to %s:%d",
			clientConn.RemoteAddr().String(), remoteHost, remotePort)

		go handleProxyConnection(clientConn, remoteHost, remotePort, protocol)
	}
}

// Обработка проксированного соединения
func handleProxyConnection(clientConn net.Conn, remoteHost string, remotePort int, protocol string) {
	defer clientConn.Close()

	// Подключаемся к удаленному хосту
	remoteAddr := fmt.Sprintf("%s:%d", remoteHost, remotePort)
	remoteConn, err := net.Dial(protocol, remoteAddr)
	if err != nil {
		common.ErrorLogger.Printf("Failed to connect to %s: %v", remoteAddr, err)
		return
	}
	defer remoteConn.Close()

	// Создаем каналы для сигналов завершения
	doneClient := make(chan bool)
	doneRemote := make(chan bool)

	// Перенаправляем трафик в обоих направлениях
	go proxyData(clientConn, remoteConn, doneClient)
	go proxyData(remoteConn, clientConn, doneRemote)

	// Ждем завершения одного из направлений
	select {
	case <-doneClient:
	case <-doneRemote:
	}

	common.InfoLogger.Printf("Proxied connection from %s to %s:%d closed",
		clientConn.RemoteAddr().String(), remoteHost, remotePort)
}

// Функция перенаправления данных между соединениями
func proxyData(src net.Conn, dst net.Conn, done chan bool) {
	buffer := make([]byte, 4096)
	for {
		n, err := src.Read(buffer)
		if err != nil {
			break
		}

		_, err = dst.Write(buffer[:n])
		if err != nil {
			break
		}
	}

	done <- true
}

// StopServer - Остановка сервера с расширенными настройками
func StopServer() {
	common.InfoLogger.Println("Stopping server...")

	// Закрываем все активные соединения
	connMutex.Lock()
	for _, conns := range activeConns {
		for _, conn := range conns {
			conn.Close()
		}
	}
	connMutex.Unlock()
}
