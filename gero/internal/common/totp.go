package common

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	totpPeriod    = 30 // Период обновления TOTP-кода (секунды)
	totpDigits    = 6  // Количество цифр в TOTP-коде
	totpSecretLen = 20 // Длина секрета в байтах (160 бит)
)

var (
	totpEnabled bool   // Флаг включения/выключения TOTP
	totpSecret  string // Секрет для генерации TOTP-кодов
)

// GenerateTOTPSecret генерирует новый случайный TOTP-секрет
func GenerateTOTPSecret() (string, error) {
	// Генерируем случайные байты для секрета
	secret := make([]byte, totpSecretLen)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	// Кодируем в base32 для удобства использования
	// Base32 используется потому что он содержит только буквы и цифры
	// и его проще вводить вручную при необходимости
	return base32.StdEncoding.EncodeToString(secret), nil
}

// SaveTOTPSecret сохраняет TOTP-секрет в файл
func SaveTOTPSecret(secret string) error {
	// Получаем директорию конфигурации
	configDir := ConfigDir()

	// Создаем директорию если не существует
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	// Путь к файлу с TOTP-секретом
	totpFilePath := filepath.Join(configDir, "totp_secret.txt")

	// Записываем секрет в файл
	err := ioutil.WriteFile(totpFilePath, []byte(secret), 0600)
	if err != nil {
		return err
	}

	// Обновляем глобальную переменную
	totpSecret = secret

	return nil
}

// LoadTOTPSecret загружает TOTP-секрет из файла
func LoadTOTPSecret() (string, error) {
	// Получаем директорию конфигурации
	configDir := ConfigDir()

	// Путь к файлу с TOTP-секретом
	totpFilePath := filepath.Join(configDir, "totp_secret.txt")

	// Проверяем существование файла
	if _, err := os.Stat(totpFilePath); os.IsNotExist(err) {
		return "", fmt.Errorf("TOTP secret file not found: %s", totpFilePath)
	}

	// Читаем секрет из файла
	data, err := ioutil.ReadFile(totpFilePath)
	if err != nil {
		return "", err
	}

	// Обновляем глобальную переменную
	totpSecret = strings.TrimSpace(string(data))

	return totpSecret, nil
}

// EnableTOTP включает или выключает TOTP-аутентификацию
func EnableTOTP(enable bool) {
	totpEnabled = enable
}

// IsTOTPEnabled возвращает статус TOTP-аутентификации
func IsTOTPEnabled() bool {
	return totpEnabled
}

// SetupTOTP создает новый TOTP-секрет и возвращает URL для QR-кода
func SetupTOTP() (string, error) {
	// Генерируем новый секрет
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", err
	}

	// Сохраняем секрет в файл
	if err := SaveTOTPSecret(secret); err != nil {
		return "", err
	}

	// Формируем URL для Google Authenticator и других TOTP-приложений
	// otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER
	issuer := "GeroTunnel"
	label := "gero@server"

	// Создаем URL для QR-кода
	qrURL := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&digits=%d&period=%d",
		label, secret, issuer, totpDigits, totpPeriod)

	return qrURL, nil
}

// ValidateTOTP проверяет корректность TOTP-кода
func ValidateTOTP(code string) bool {
	// Проверяем что TOTP включен и есть секрет
	if !totpEnabled || totpSecret == "" {
		return true // Если TOTP не используется, всегда возвращаем true
	}

	// Получаем текущее время в секундах
	now := time.Now().Unix()

	// Проверяем код для текущего и предыдущего временного окна
	// чтобы учесть небольшую рассинхронизацию часов
	return calculateTOTP(totpSecret, now) == code ||
		calculateTOTP(totpSecret, now-totpPeriod) == code
}

// calculateTOTP вычисляет TOTP-код для заданного секрета и времени
func calculateTOTP(secret string, timestamp int64) string {
	// Вычисляем временное окно
	timeWindow := timestamp / totpPeriod

	// Конвертируем timeWindow в 8-байтовый массив
	challenge := make([]byte, 8)
	binary.BigEndian.PutUint64(challenge, uint64(timeWindow))

	// Декодируем секрет из base32
	secretBytes, err := base32.StdEncoding.DecodeString(padBase32(secret))
	if err != nil {
		return ""
	}

	// Вычисляем HMAC-SHA1
	h := hmac.New(sha1.New, secretBytes)
	h.Write(challenge)
	hmacResult := h.Sum(nil)

	// Используем последний байт как смещение
	offset := int(hmacResult[len(hmacResult)-1] & 0x0F)

	// Берем 4 байта начиная со смещения
	binCode := binary.BigEndian.Uint32(hmacResult[offset : offset+4])

	// Маскируем старший бит и берем нужное количество цифр
	binCode = binCode & 0x7FFFFFFF
	otp := binCode % uint32(pow10(totpDigits))

	// Форматируем результат с нужным количеством цифр
	result := fmt.Sprintf(fmt.Sprintf("%%0%dd", totpDigits), otp)

	return result
}

// padBase32 добавляет '=' в конец строки для правильного декодирования base32
func padBase32(s string) string {
	padCount := 8 - (len(s) % 8)
	if padCount < 8 {
		return s + strings.Repeat("=", padCount)
	}
	return s
}

// pow10 возвращает 10 в степени n
func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}

// GenerateTOTPQR создает QR-код для TOTP-секрета (упрощенная версия)
func GenerateTOTPQR(totpURL string, filePath string) error {
	// В этой версии просто сохраняем URL в файл
	// В реальной реализации здесь можно было бы генерировать QR-код
	return ioutil.WriteFile(filePath, []byte(totpURL), 0600)
}
