package app

import (
	grpcapp "ssoq/internal/app/grpc"
	"ssoq/internal/services/auth"
	"ssoq/internal/storage"
	"time"

	"github.com/sirupsen/logrus"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *logrus.Logger, grpcPort int, connectionString string, tokenTTL time.Duration) *App {
	storage, err := storage.NewDB(connectionString)
	if err != nil {
		log.Fatal("failed to create storage", err)
	}
	auth := auth.NewAuth(log, storage, storage, storage, storage, storage, tokenTTL)
	grpcServer := grpcapp.New(log, auth, grpcPort)
	return &App{
		GRPCServer: grpcServer,
	}
}
