package grpcapp

import (
	"fmt"
	"net"
	authgrpc "ssoq/internal/server/grpc"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type App struct {
	log        *logrus.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *logrus.Logger, auth authgrpc.Auth, port int) *App {

	gRPCServer := grpc.NewServer()
	authgrpc.Register(gRPCServer, auth)
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}
func (a *App) Run() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	return a.gRPCServer.Serve(lis)
}
func (a *App) Stop() {
	a.gRPCServer.GracefulStop()
}
func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		a.log.Fatal("failed to run gRPC server", err)
	}
}
