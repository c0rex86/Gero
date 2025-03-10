package client

import (
	"fmt"
)

type UDPTunnelInfo struct {
	LocalPort  uint16
	RemotePort uint16
	Status     string
}

func CreateUDPTunnel(serverAddr string, serverPort int, key string, localPort, remotePort uint16) error {
	if err := Init(); err != nil {
		return fmt.Errorf("error initializing client: %w", err)
	}

	if serverConn == nil {
		err := connectToServer(serverAddr, serverPort, key)
		if err != nil {
			return fmt.Errorf("failed to connect to server: %w", err)
		}
	}

	go createUDPProxy(remotePort, localPort)

	fmt.Printf("UDP tunnel creation initiated from local port %d to remote port %d\n", localPort, remotePort)
	fmt.Println("If no port was specified (0), the actual assigned port will be shown in logs")

	return nil
}

func ListUDPTunnels() []UDPTunnelInfo {
	udpProxiesMutex.RLock()
	defer udpProxiesMutex.RUnlock()

	tunnels := make([]UDPTunnelInfo, 0, len(udpProxies))
	for serverPort, proxy := range udpProxies {
		status := "active"
		if proxy.Closed {
			status = "closing"
		}

		tunnels = append(tunnels, UDPTunnelInfo{
			LocalPort:  proxy.LocalPort,
			RemotePort: serverPort,
			Status:     status,
		})
	}

	return tunnels
}

func CloseUDPTunnel(localPort uint16) bool {
	udpProxiesMutex.RLock()
	var targetProxy *UDPProxy
	var serverPort uint16

	for port, proxy := range udpProxies {
		if proxy.LocalPort == localPort {
			targetProxy = proxy
			serverPort = port
			break
		}
	}
	udpProxiesMutex.RUnlock()

	if targetProxy == nil {
		return false
	}

	// Маркируем как закрытый
	targetProxy.Closed = true

	// Закрываем слушатель если есть
	if targetProxy.UDPListener != nil {
		targetProxy.UDPListener.Close()
	}

	// Удаляем из списка
	udpProxiesMutex.Lock()
	delete(udpProxies, serverPort)
	udpProxiesMutex.Unlock()

	return true
}

func GetUDPTunnelInfo(localPort uint16) (UDPTunnelInfo, bool) {
	udpProxiesMutex.RLock()
	defer udpProxiesMutex.RUnlock()

	for serverPort, proxy := range udpProxies {
		if proxy.LocalPort == localPort {
			status := "active"
			if proxy.Closed {
				status = "closing"
			}

			return UDPTunnelInfo{
				LocalPort:  proxy.LocalPort,
				RemotePort: serverPort,
				Status:     status,
			}, true
		}
	}

	return UDPTunnelInfo{}, false
}

func RunUDPClient(serverAddr string, serverPort int, key string) error {
	if err := Init(); err != nil {
		return fmt.Errorf("error initializing client: %w", err)
	}

	// Запуск в standalone режиме для UDP (без TCP)
	err := connectToServer(serverAddr, serverPort, key)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	fmt.Printf("Connected to %s, waiting for UDP tunnel setup...\n", serverConn.RemoteAddr())

	// Ожидаем завершения всех туннелей или контекста
	select {
	case <-ctx.Done():
		fmt.Println("Client shutting down...")
		return nil
	}
}
