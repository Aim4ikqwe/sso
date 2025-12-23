package app

import (
	grpcapp "ssoq/internal/app/grpc"
	providerjwt "ssoq/internal/jwt"
	"ssoq/internal/services/auth"
	"ssoq/internal/storage"
	"time"

	"github.com/sirupsen/logrus"
)

// App represents the main application that contains the gRPC server
type App struct {
	GRPCServer *grpcapp.App
}

// New creates a new instance of the application with the provided configuration
// It initializes the database storage, authentication service, and gRPC server
func New(log *logrus.Logger, grpcPort int, connectionString string, tokenTTL time.Duration) *App {
	// Initialize JWT package logger
	providerjwt.SetLogger(log)

	storage, err := storage.NewDB(connectionString, log)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("failed to create storage")
	}
	auth := auth.NewAuth(log, storage, storage, storage, storage, storage, tokenTTL)
	grpcServer := grpcapp.New(log, auth, grpcPort)

	log.WithFields(logrus.Fields{
		"port": grpcPort,
	}).Info("application initialized successfully")

	return &App{
		GRPCServer: grpcServer,
	}
}
