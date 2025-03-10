package client

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/c0rex86/gero/internal/common"
)

// TCPRouteInfo содержит информацию о настроенном TCP-маршруте
type TCPRouteInfo struct {
	LocalPort   uint16
	RemoteHost  string
	RemotePort  uint16
	Status      string
	Connections int
}

var (
	tcpRoutes      = make(map[string]*TCPRoute)
	tcpRoutesMutex sync.RWMutex
)

// TCPRoute представляет настроенный TCP-маршрут
type TCPRoute struct {
	LocalPort   uint16
	RemoteHost  string
	RemotePort  uint16
	Listener    net.Listener
	Connections map[string]net.Conn
	ConnLock    sync.RWMutex
	Closed      bool
}

// CreateTCPRoute создает новый TCP-маршрут
func CreateTCPRoute(localPort uint16, remoteHost string, remotePort uint16) (uint16, error) {
	if err := Init(); err != nil {
		return 0, fmt.Errorf("error initializing client: %w", err)
	}

	if serverConn == nil {
		err := connectToServer("", 0, "")
		if err != nil {
			return 0, fmt.Errorf("failed to connect to server: %w", err)
		}
	}

	// Создаем локальный TCP-слушатель
	var listener net.Listener
	var actualPort uint16
	var err error

	if localPort > 0 {
		// Слушаем на указанном порту
		addr := fmt.Sprintf("127.0.0.1:%d", localPort)
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return 0, fmt.Errorf("failed to bind local TCP port %d: %w", localPort, err)
		}
		actualPort = localPort
	} else {
		// Автоматический выбор порта
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, fmt.Errorf("failed to bind local TCP port: %w", err)
		}
		actualPort = uint16(listener.Addr().(*net.TCPAddr).Port)
	}

	// Отправляем команду создания TCP-прокси на сервер
	cmdData := make([]byte, 5+len(remoteHost))
	cmdData[0] = 1 // Команда CreateTCPProxy
	cmdData[1] = byte(localPort >> 8)
	cmdData[2] = byte(localPort)
	cmdData[3] = byte(remotePort >> 8)
	cmdData[4] = byte(remotePort)
	copy(cmdData[5:], []byte(remoteHost))

	err = common.WriteHeader(serverConn, common.Header{
		Type:       common.TypeControl,
		PayloadLen: uint32(len(cmdData)),
	})
	if err != nil {
		listener.Close()
		return 0, fmt.Errorf("error sending TCP proxy creation command: %w", err)
	}

	_, err = serverConn.Write(cmdData)
	if err != nil {
		listener.Close()
		return 0, fmt.Errorf("error sending TCP proxy creation command: %w", err)
	}

	// Создаем и регистрируем маршрут
	route := &TCPRoute{
		LocalPort:   actualPort,
		RemoteHost:  remoteHost,
		RemotePort:  remotePort,
		Listener:    listener,
		Connections: make(map[string]net.Conn),
		ConnLock:    sync.RWMutex{},
	}

	routeKey := fmt.Sprintf("%d", actualPort)
	tcpRoutesMutex.Lock()
	tcpRoutes[routeKey] = route
	tcpRoutesMutex.Unlock()

	common.InfoLogger.Printf("Created TCP route from local port %d to %s:%d",
		actualPort, remoteHost, remotePort)

	// Запускаем обработчик соединений
	go handleTCPRoute(route)

	return actualPort, nil
}

// CloseTCPRoute закрывает TCP-маршрут
func CloseTCPRoute(localPort uint16) bool {
	portStr := fmt.Sprintf("%d", localPort)

	tcpRoutesMutex.RLock()
	route, exists := tcpRoutes[portStr]
	tcpRoutesMutex.RUnlock()

	if !exists || route.Closed {
		return false
	}

	// Закрываем слушатель
	if route.Listener != nil {
		route.Listener.Close()
	}

	// Закрываем все соединения
	route.ConnLock.Lock()
	for _, conn := range route.Connections {
		conn.Close()
	}
	route.ConnLock.Unlock()

	route.Closed = true

	// Удаляем из карты маршрутов
	tcpRoutesMutex.Lock()
	delete(tcpRoutes, portStr)
	tcpRoutesMutex.Unlock()

	// Отправляем команду закрытия прокси на сервер
	if serverConn != nil {
		cmdData := make([]byte, 3)
		cmdData[0] = 2 // Команда CloseTCPProxy
		cmdData[1] = byte(localPort >> 8)
		cmdData[2] = byte(localPort)

		err := common.WriteHeader(serverConn, common.Header{
			Type:       common.TypeControl,
			PayloadLen: uint32(len(cmdData)),
		})
		if err == nil {
			serverConn.Write(cmdData)
		}
	}

	common.InfoLogger.Printf("Closed TCP route on local port %d", localPort)
	return true
}

// ListTCPRoutes возвращает список TCP-маршрутов
func ListTCPRoutes() []TCPRouteInfo {
	tcpRoutesMutex.RLock()
	defer tcpRoutesMutex.RUnlock()

	routes := make([]TCPRouteInfo, 0, len(tcpRoutes))
	for _, route := range tcpRoutes {
		status := "active"
		if route.Closed {
			status = "closing"
		}

		route.ConnLock.RLock()
		connCount := len(route.Connections)
		route.ConnLock.RUnlock()

		routes = append(routes, TCPRouteInfo{
			LocalPort:   route.LocalPort,
			RemoteHost:  route.RemoteHost,
			RemotePort:  route.RemotePort,
			Status:      status,
			Connections: connCount,
		})
	}

	return routes
}

// GetTCPRouteInfo возвращает информацию о маршруте по локальному порту
func GetTCPRouteInfo(localPort uint16) (TCPRouteInfo, bool) {
	portStr := fmt.Sprintf("%d", localPort)

	tcpRoutesMutex.RLock()
	route, exists := tcpRoutes[portStr]
	tcpRoutesMutex.RUnlock()

	if !exists {
		return TCPRouteInfo{}, false
	}

	status := "active"
	if route.Closed {
		status = "closing"
	}

	route.ConnLock.RLock()
	connCount := len(route.Connections)
	route.ConnLock.RUnlock()

	return TCPRouteInfo{
		LocalPort:   route.LocalPort,
		RemoteHost:  route.RemoteHost,
		RemotePort:  route.RemotePort,
		Status:      status,
		Connections: connCount,
	}, true
}

// handleTCPRoute обрабатывает входящие подключения к TCP-маршруту
func handleTCPRoute(route *TCPRoute) {
	defer func() {
		if route.Listener != nil && !route.Closed {
			route.Listener.Close()
		}

		// Закрываем все соединения
		route.ConnLock.Lock()
		for _, conn := range route.Connections {
			conn.Close()
		}
		route.ConnLock.Unlock()
	}()

	for {
		if route.Closed {
			return
		}

		// Установка таймаута для Accept
		route.Listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		conn, err := route.Listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}

			common.ErrorLogger.Printf("Error accepting connection on TCP route port %d: %v",
				route.LocalPort, err)
			continue
		}

		// Обрабатываем новое подключение
		go handleTCPRouteConnection(route, conn)
	}
}

// handleTCPRouteConnection обрабатывает одно TCP-соединение
func handleTCPRouteConnection(route *TCPRoute, conn net.Conn) {
	if route.Closed || serverConn == nil {
		conn.Close()
		return
	}

	// Генерируем уникальный ID для соединения
	connID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())

	// Регистрируем соединение
	route.ConnLock.Lock()
	route.Connections[connID] = conn
	route.ConnLock.Unlock()

	defer func() {
		conn.Close()

		route.ConnLock.Lock()
		delete(route.Connections, connID)
		route.ConnLock.Unlock()
	}()

	// Копируем данные от клиента к серверу
	buf := make([]byte, 32*1024)
	for {
		if route.Closed || serverConn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				common.ErrorLogger.Printf("Error reading from TCP route connection: %v", err)
			}
			return
		}

		// Формируем заголовок: [connID (4 байта)][данные]
		// В данном случае connID - это первые 4 байта хеша от полного connID
		connIDHash := hashString(connID)

		// Формируем пакет с данными и идентификатором соединения
		dataWithHeader := make([]byte, 4+n)
		copy(dataWithHeader[0:4], connIDHash[:4])
		copy(dataWithHeader[4:], buf[:n])

		// Отправляем данные на сервер
		err = common.WriteHeader(serverConn, common.Header{
			Type:       common.TypeData,
			PayloadLen: uint32(len(dataWithHeader)),
		})
		if err != nil {
			common.ErrorLogger.Printf("Error sending TCP data header to server: %v", err)
			return
		}

		_, err = serverConn.Write(dataWithHeader)
		if err != nil {
			common.ErrorLogger.Printf("Error sending TCP data to server: %v", err)
			return
		}
	}
}

// hashString создает простой хеш строки
func hashString(s string) [16]byte {
	var result [16]byte
	for i := 0; i < len(s) && i < 16; i++ {
		result[i%16] ^= s[i]
	}
	return result
}
