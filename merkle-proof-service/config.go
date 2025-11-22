package main

import (
	"os"
	"strconv"
)

type Config struct {
	Port int
}

func LoadConfig() *Config {
	port := 8090
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return &Config{Port: port}
}

