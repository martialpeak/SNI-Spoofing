package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	ListenAddr  = "127.0.0.1:1080"
	ConnectIP   = "8.8.8.8" // آی‌پی سرور شما
	ConnectPort = "443"     // پورت سرور شما
)

func main() {
	// ساخت سرور محلی
	listener, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", ListenAddr, err)
	}
	defer listener.Close()

	fmt.Printf("Proxy is running on %s\n", ListenAddr)
	fmt.Println("Waiting for connections...")

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// پردازش هر کلاینت در یک Goroutine مجزا (بسیار سبک‌تر از Thread یا Asyncio)
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// اتصال به سرور هدف
	serverAddr := fmt.Sprintf("%s:%s", ConnectIP, ConnectPort)
	serverConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("Failed to connect to server %s: %v", serverAddr, err)
		return
	}
	defer serverConn.Close()

	// ایجاد دو مسیر برای انتقال داده‌ها (رله کردن دوطرفه)
	errChan := make(chan error, 2)

	// کپی از کلاینت به سرور
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		errChan <- err
	}()

	// کپی از سرور به کلاینت
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		errChan <- err
	}()

	// منتظر ماندن تا زمانی که یکی از ارتباط‌ها قطع شود
	<-errChan
}
