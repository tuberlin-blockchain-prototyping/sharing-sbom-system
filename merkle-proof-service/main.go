package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"merkle-proof-service/handlers"
	"merkle-proof-service/service"
)

func main() {
	config := LoadConfig()

	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	storage, err := service.NewStorage("./data/smts.db")
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer storage.Close()

	svc := service.NewSMTService(storage)
	h := handlers.NewHandler(svc)

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/health", h.Health)
	router.GET("/smt/:root", h.GetSMT)
	router.POST("/build", h.Build)
	router.POST("/store-smt", h.StoreSMT)
	router.POST("/prove-batch", h.ProveBatch)

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: router,
	}

	go func() {
		log.Printf("Server starting on port %d", config.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}

	log.Println("Bye")
}

