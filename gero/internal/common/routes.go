package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RouteConfig представляет конфигурацию одного маршрута
type RouteConfig struct {
	Name       string `json:"name"`        // Уникальное имя маршрута
	LocalPort  int    `json:"local_port"`  // Локальный порт для проксирования
	RemoteHost string `json:"remote_host"` // Удаленный хост
	RemotePort int    `json:"remote_port"` // Удаленный порт
	Protocol   string `json:"protocol"`    // Протокол (tcp/udp)
}

// RoutesConfig содержит список всех настроенных маршрутов
type RoutesConfig struct {
	Routes []RouteConfig `json:"routes"`
}

var (
	routesConfig RoutesConfig
	routesMutex  sync.Mutex
	routesLoaded bool
)

// LoadRoutes загружает конфигурацию маршрутов из JSON-файла
func LoadRoutes() ([]RouteConfig, error) {
	routesMutex.Lock()
	defer routesMutex.Unlock()

	// Получаем директорию конфигурации
	configDir := ConfigDir()

	// Путь к файлу маршрутов
	routesFilePath := filepath.Join(configDir, "routes.json")

	// Проверяем существование файла
	if _, err := os.Stat(routesFilePath); os.IsNotExist(err) {
		// Файл не существует, создаем пустую конфигурацию
		routesConfig = RoutesConfig{
			Routes: []RouteConfig{},
		}

		// Создаем директорию если не существует
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, err
		}

		// Сохраняем пустую конфигурацию
		if err := SaveRoutes(); err != nil {
			return nil, err
		}

		routesLoaded = true
		return routesConfig.Routes, nil
	}

	// Открываем файл
	file, err := os.Open(routesFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Декодируем JSON
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&routesConfig); err != nil {
		return nil, err
	}

	routesLoaded = true
	return routesConfig.Routes, nil
}

// SaveRoutes сохраняет конфигурацию маршрутов в JSON-файл
func SaveRoutes() error {
	routesMutex.Lock()
	defer routesMutex.Unlock()

	// Получаем директорию конфигурации
	configDir := ConfigDir()

	// Создаем директорию если не существует
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	// Путь к файлу маршрутов
	routesFilePath := filepath.Join(configDir, "routes.json")

	// Открываем файл для записи
	file, err := os.Create(routesFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Кодируем в JSON с отступами для читаемости
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(routesConfig); err != nil {
		return err
	}

	return nil
}

// AddRoute добавляет или обновляет маршрут
func AddRoute(route RouteConfig) error {
	// Загружаем маршруты если еще не загружены
	if !routesLoaded {
		if _, err := LoadRoutes(); err != nil {
			return err
		}
	}

	routesMutex.Lock()
	defer routesMutex.Unlock()

	// Ищем маршрут с таким именем
	for i, r := range routesConfig.Routes {
		if r.Name == route.Name {
			// Обновляем существующий маршрут
			routesConfig.Routes[i] = route
			return SaveRoutes()
		}
	}

	// Добавляем новый маршрут
	routesConfig.Routes = append(routesConfig.Routes, route)
	return SaveRoutes()
}

// RemoveRoute удаляет маршрут по имени
func RemoveRoute(name string) error {
	// Загружаем маршруты если еще не загружены
	if !routesLoaded {
		if _, err := LoadRoutes(); err != nil {
			return err
		}
	}

	routesMutex.Lock()
	defer routesMutex.Unlock()

	// Ищем маршрут для удаления
	found := false
	newRoutes := []RouteConfig{}
	for _, route := range routesConfig.Routes {
		if route.Name != name {
			newRoutes = append(newRoutes, route)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("route not found: %s", name)
	}

	routesConfig.Routes = newRoutes
	return SaveRoutes()
}

// GetRoutes возвращает все настроенные маршруты
func GetRoutes() ([]RouteConfig, error) {
	// Загружаем маршруты если еще не загружены
	if !routesLoaded {
		return LoadRoutes()
	}

	routesMutex.Lock()
	defer routesMutex.Unlock()

	routes := make([]RouteConfig, len(routesConfig.Routes))
	copy(routes, routesConfig.Routes)
	return routes, nil
}

// GetRoute возвращает маршрут по имени
func GetRoute(name string) (RouteConfig, error) {
	// Загружаем маршруты если еще не загружены
	if !routesLoaded {
		if _, err := LoadRoutes(); err != nil {
			return RouteConfig{}, err
		}
	}

	routesMutex.Lock()
	defer routesMutex.Unlock()

	// Ищем маршрут по имени
	for _, route := range routesConfig.Routes {
		if route.Name == name {
			return route, nil
		}
	}

	return RouteConfig{}, fmt.Errorf("route not found: %s", name)
}
