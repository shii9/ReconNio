package utils

import (
	"log"
	"os"
)

var (
	Info  *log.Logger
	Error *log.Logger
)

func InitLogger(logPath string) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Cannot open log file: %v", err)
	}

	Info = log.New(logFile, "[INFO] ", log.LstdFlags|log.Lshortfile)
	Error = log.New(logFile, "[ERROR] ", log.LstdFlags|log.Lshortfile)
}
