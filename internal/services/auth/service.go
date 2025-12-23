package auth

import (
	"context"
	"fmt"
	providerjwt "ssoq/internal/jwt"
	"ssoq/internal/model"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	log           *logrus.Logger
	userSaver     UserSaver
	userProvider  UserProvider
	appProvider   AppProvider
	tokenSaver    TokenSaver
	tokenProvider TokenProvider
	tokenTTL      time.Duration
}
type UserSaver interface {
	SaveUser(ctx context.Context, email string, password string, username string, app_id int64) (int64, error)
}
type UserProvider interface {
	GetUser(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id int64) (*model.User, error)
}
type AppProvider interface {
	App(ctx context.Context, app_id int64) (*model.App, error)
}
type TokenSaver interface {
	SaveToken(ctx context.Context, user_id int64, token string) error
}
type TokenProvider interface {
	DeleteToken(ctx context.Context, user_id int64) error
	GetToken(ctx context.Context, user_id int64) (string, error)
}

func NewAuth(log *logrus.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, tokenSaver TokenSaver, tokenProvider TokenProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:           log,
		userSaver:     userSaver,
		userProvider:  userProvider,
		appProvider:   appProvider,
		tokenSaver:    tokenSaver,
		tokenProvider: tokenProvider,
		tokenTTL:      tokenTTL,
	}
}

func (a *Auth) Login(ctx context.Context, email string, password string, app_id int64) (bool, string, string, error) {
	if email == "" || password == "" {
		return false, "", "", fmt.Errorf("email and password are required")
	}

	user, err := a.userProvider.GetUser(ctx, email)
	if err != nil {
		return false, "", "", err
	}
	if user == nil {
		return false, "", "", nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return false, "", "", err
	}
	app, err := a.appProvider.App(ctx, app_id)
	if err != nil {
		return false, "", "", fmt.Errorf("appProvider.App: %w", err)
	}

	access_token, refresh_token, err := providerjwt.GenerateToken(app, user, a.tokenTTL)
	if err != nil {
		return false, "", "", err
	}
	if err := a.tokenSaver.SaveToken(ctx, user.Id, refresh_token); err != nil {
		return false, "", "", err
	}
	a.log.Info("user logged in successfully")
	return true, access_token, refresh_token, nil
}

func (a *Auth) Register(ctx context.Context, email string, password string, username string, app_id int64) (bool, int64, error) {
	if email == "" || password == "" || username == "" {
		return false, 0, fmt.Errorf("email, password and username are required")
	}

	if len(password) < 8 {
		return false, 0, fmt.Errorf("password is too short")
	}

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, 0, err
	}
	user_id, err := a.userSaver.SaveUser(ctx, email, string(encryptedPassword), username, app_id)
	if err != nil {
		return false, 0, err
	}
	a.log.Info("user registered successfully")
	return true, user_id, nil
}
func (a *Auth) Logout(ctx context.Context, providedToken string, app_id int64) (bool, error) {
	const op = "auth.Logout"

	app, err := a.appProvider.App(ctx, app_id)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	token, err := providerjwt.ParseToken(providedToken, app)
	if err != nil {
		return false, fmt.Errorf("%s: invalid token: %w", op, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return false, fmt.Errorf("%s: invalid token claims", op)
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		return false, fmt.Errorf("%s: invalid user_id in token", op)
	}
	userID := int64(userIDFloat)

	if err := a.tokenProvider.DeleteToken(ctx, userID); err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("user logged out successfully")
	return true, nil
}
func (a *Auth) RefreshToken(ctx context.Context, providedToken string, app_id int64) (string, string, error) {
	const op = "auth.RefreshToken"

	app, err := a.appProvider.App(ctx, app_id)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := providerjwt.ParseToken(providedToken, app)
	if err != nil {
		return "", "", fmt.Errorf("%s: invalid token: %w", op, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("%s: invalid token claims", op)
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		return "", "", fmt.Errorf("%s: invalid user_id in token", op)
	}
	userID := int64(userIDFloat)

	if claims["purpose"] != "refresh" {
		return "", "", fmt.Errorf("%s: invalid token purpose", op)
	}

	// Compare with token in DB
	dbToken, err := a.tokenProvider.GetToken(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if dbToken == "" || dbToken != providedToken {
		return "", "", fmt.Errorf("%s: token is revoked or invalid", op)
	}

	user, err := a.userProvider.GetUserByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	if user == nil {
		return "", "", fmt.Errorf("%s: user not found", op)
	}

	// Generate new pair
	accessToken, newRefreshToken, err := providerjwt.GenerateToken(app, user, a.tokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// Update token in DB (Rotation)
	if err := a.tokenSaver.SaveToken(ctx, user.Id, newRefreshToken); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	a.log.Info("token refreshed successfully")
	return accessToken, newRefreshToken, nil
}
