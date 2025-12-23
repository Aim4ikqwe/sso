package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ssov1 "github.com/Aim4ikqwe/ssoprotos/gen/go/sso"
)

type Server struct {
	ssov1.SSOServer
	Auth Auth
}

type Auth interface {
	Login(ctx context.Context, email string, password string, app_id int64) (bool, string, string, error)
	Register(ctx context.Context, email string, password string, username string, app_id int64) (bool, int64, error)
	Logout(ctx context.Context, token string, app_id int64) (bool, error)
	RefreshToken(ctx context.Context, token string, app_id int64) (string, string, error)
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterSSOServer(gRPC, &Server{Auth: auth})
}

func (s *Server) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	success, access_token, refresh_token, err := s.Auth.Login(ctx, req.Email, req.Password, req.AppId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &ssov1.LoginResponse{Success: success, AccessToken: access_token, RefreshToken: refresh_token}, nil
}

func (s *Server) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	success, id, err := s.Auth.Register(ctx, req.Email, req.Password, req.Username, req.AppId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &ssov1.RegisterResponse{Success: success, UserId: id}, nil
}

func (s *Server) Logout(ctx context.Context, req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	success, err := s.Auth.Logout(ctx, req.Token, req.AppId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &ssov1.LogoutResponse{Success: success}, nil
}

func (s *Server) RefreshToken(ctx context.Context, req *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}
	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "app_id is required")
	}

	access_token, refresh_token, err := s.Auth.RefreshToken(ctx, req.RefreshToken, req.AppId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &ssov1.RefreshResponse{AccessToken: access_token, RefreshToken: refresh_token}, nil
}
