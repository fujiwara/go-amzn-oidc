package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	validator "github.com/fujiwara/go-amzn-oidc/validator"
	"github.com/hashicorp/logutils"
)

func main() {
	var (
		port     int
		host     string
		timeout  time.Duration
		logLevel string
	)
	flag.IntVar(&port, "port", 8080, "Listen port")
	flag.StringVar(&host, "host", "127.0.0.1", "Listen host")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "Timeout for validation")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.VisitAll(envToFlag)
	flag.Parse()

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"debug", "info", "warn", "error"},
		MinLevel: logutils.LogLevel(logLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

	http.HandleFunc("/", validator.NewHTTPHandlerFunc(timeout))

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Println("[info] Listening", addr)

	log.Fatal(http.ListenAndServe(addr, nil))
}

func envToFlag(f *flag.Flag) {
	name := strings.ToUpper(strings.Replace(f.Name, "-", "_", -1))
	if s, ok := os.LookupEnv(name); ok {
		f.Value.Set(s)
	}
}
