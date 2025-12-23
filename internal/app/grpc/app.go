package grpcapp

import (
	"fmt"
	"net"
	authgrpc "ssoq/internal/server/grpc"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// App represents the gRPC application server
type App struct {
	log        *logrus.Logger
	gRPCServer *grpc.Server
	port       int
}

// New creates a new instance of the gRPC application with the provided logger, authentication service and port
func New(log *logrus.Logger, auth authgrpc.Auth, port int) *App {
	gRPCServer := grpc.NewServer()
	authgrpc.Register(gRPCServer, auth)
	
	log.WithFields(logrus.Fields{
		"port": port,
	}).Info("gRPC server initialized")
	
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

// Run starts the gRPC server on the configured port
// It creates a listener and serves the gRPC server until an error occurs
func (a *App) Run() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"port":  a.port,
			"error": err,
		}).Error("failed to listen on port")
		return fmt.Errorf("failed to listen: %v", err)
	}
	
	a.log.WithFields(logrus.Fields{
		"port": a.port,
	}).Info("gRPC server listening")
	
	return a.gRPCServer.Serve(lis)
}

// Stop gracefully stops the gRPC server
func (a *App) Stop() {
	a.gRPCServer.GracefulStop()
	a.log.Info("gRPC server stopped")
}

// MustRun starts the gRPC server and logs a fatal error if it fails
func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		a.log.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("failed to run gRPC server")
	}
}
