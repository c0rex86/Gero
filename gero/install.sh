#!/bin/bash
# Gero - Quick install script
# c0rex86 https://github.com/c0rex86/gero

set -e

# Check if we're running as root
if [ "$(id -u)" -eq 0 ]; then
    echo "Эй, не запускай от рута! Используй sudo в конце, если нужно."
    exit 1
fi

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "Упс, git не установлен. Ставим..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y git
    elif command -v yum &> /dev/null; then
        sudo yum install -y git
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm git
    elif command -v brew &> /dev/null; then
        brew install git
    else
        echo "Не могу установить git автоматически. Поставь его сам и попробуй снова."
        exit 1
    fi
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Go не найден. Нужно поставить Go 1.16+ для сборки."
    echo "Запусти следующие команды:"
    echo "curl -sSL https://golang.org/dl/go1.20.1.linux-amd64.tar.gz -o go.tar.gz"
    echo "sudo tar -C /usr/local -xzf go.tar.gz"
    echo "echo 'export PATH=\$PATH:/usr/local/go/bin' >> ~/.bashrc"
    echo "source ~/.bashrc"
    exit 1
fi

# Create temp directory
TEMP_DIR=$(mktemp -d)
echo "Создаю временную директорию: $TEMP_DIR"

# Clone repository
echo "Клонирую репозиторий Gero..."
git clone https://github.com/c0rex86/gero.git "$TEMP_DIR/gero"
cd "$TEMP_DIR/gero"

# Build and install
echo "Собираю Gero..."
make

echo "Устанавливаю Gero..."
sudo make install

# Verify installation
if command -v gero &> /dev/null; then
    echo "Gero успешно установлен!"
    gero version
    echo ""
    echo "Быстрый старт:"
    echo "1. Настрой ключ: gero config set-key \"мойкрутойключ\""
    echo "2. Запусти сервер: gero server"
    echo "3. На другой машине: gero client --server адрес.сервера --key \"мойкрутойключ\""
    echo ""
    echo "Полная документация: https://github.com/c0rex86/gero"
else
    echo "Что-то пошло не так. Попробуй ручную установку."
fi

# Clean up
echo "Удаляю временные файлы..."
rm -rf "$TEMP_DIR"

echo "Готово!" 