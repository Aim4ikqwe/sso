package main

import (
	"fmt"
	"os"
	"os/signal"
	"ssoq/internal/app"
	"ssoq/internal/config"
	"syscall"

	"github.com/sirupsen/logrus"
)

func main() {
	cfg := config.MustLoad()
	log := initLogger(cfg)
	fmt.Println(cfg.ConnectionString())
	log.Info("app started")
	application := app.New(log, cfg.Grpc.Port, cfg.ConnectionString(), cfg.TokenTTL)
	go func() {
		if err := application.GRPCServer.Run(); err != nil {
			log.Error("app.GRPCServer.Run: ", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("stopping application", sign)

	application.GRPCServer.Stop()
	log.Info("application stopped")
}
func initLogger(cfg *config.Config) *logrus.Logger {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	switch cfg.Env {
	case "local":
		log.SetLevel(logrus.DebugLevel)
	case "staging":
		log.SetLevel(logrus.InfoLevel)
	case "production":
		log.SetLevel(logrus.ErrorLevel)
	}
	logrus.SetOutput(os.Stdout)
	return log
}
