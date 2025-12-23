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

// Auth represents the authentication service that handles user authentication operations
type Auth struct {
	log           *logrus.Logger
	userSaver     UserSaver
	userProvider UserProvider
	appProvider   AppProvider
	tokenSaver    TokenSaver
	tokenProvider TokenProvider
	tokenTTL      time.Duration
}

// UserSaver interface defines methods for saving user data
type UserSaver interface {
	SaveUser(ctx context.Context, email string, password string, username string, app_id int64) (int64, error)
}

// UserProvider interface defines methods for retrieving user data
type UserProvider interface {
	GetUser(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id int64) (*model.User, error)
}

// AppProvider interface defines methods for retrieving application data
type AppProvider interface {
	App(ctx context.Context, app_id int64) (*model.App, error)
}

// TokenSaver interface defines methods for saving tokens
type TokenSaver interface {
	SaveToken(ctx context.Context, user_id int64, token string) error
}

// TokenProvider interface defines methods for managing tokens
type TokenProvider interface {
	DeleteToken(ctx context.Context, user_id int64) error
	GetToken(ctx context.Context, user_id int64) (string, error)
}

// NewAuth creates a new instance of the Auth service with the provided dependencies
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

// Login authenticates a user with email and password, and returns access and refresh tokens if successful
// It validates credentials, checks user existence, verifies password, and generates JWT tokens
func (a *Auth) Login(ctx context.Context, email string, password string, app_id int64) (bool, string, string, error) {
	if email == "" || password == "" {
		a.log.WithFields(logrus.Fields{
			"email":  email,
			"app_id": app_id,
		}).Error("email and password are required for login")
		return false, "", "", fmt.Errorf("email and password are required")
	}

	user, err := a.userProvider.GetUser(ctx, email)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"email": email,
			"error": err,
		}).Error("failed to get user from provider")
		return false, "", "", err
	}
	if user == nil {
		a.log.WithField("email", email).Warn("user not found during login")
		return false, "", "", nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		a.log.WithField("email", email).Warn("invalid password provided")
		return false, "", "", err
	}
	app, err := a.appProvider.App(ctx, app_id)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"error":  err,
		}).Error("failed to get app from provider")
		return false, "", "", fmt.Errorf("appProvider.App: %w", err)
	}

	access_token, refresh_token, err := providerjwt.GenerateToken(app, user, a.tokenTTL)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": user.Id,
			"app_id":  app_id,
			"error":   err,
		}).Error("failed to generate tokens")
		return false, "", "", err
	}
	if err := a.tokenSaver.SaveToken(ctx, user.Id, refresh_token); err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": user.Id,
			"error":   err,
		}).Error("failed to save refresh token")
		return false, "", "", err
	}
	a.log.WithFields(logrus.Fields{
		"user_id": user.Id,
		"app_id":  app_id,
		"email":   email,
	}).Info("user logged in successfully")
	return true, access_token, refresh_token, nil
}

// Register creates a new user with the provided email, password, username and app_id
// It validates input parameters, encrypts the password, and saves the user to the database
func (a *Auth) Register(ctx context.Context, email string, password string, username string, app_id int64) (bool, int64, error) {
	if email == "" || password == "" || username == "" {
		a.log.WithFields(logrus.Fields{
			"email":    email,
			"username": username,
			"app_id":   app_id,
		}).Error("email, password and username are required for registration")
		return false, 0, fmt.Errorf("email, password and username are required")
	}

	if len(password) < 8 {
		a.log.WithField("email", email).Error("password is too short for registration")
		return false, 0, fmt.Errorf("password is too short")
	}

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"email": email,
			"error": err,
		}).Error("failed to encrypt password")
		return false, 0, err
	}
	user_id, err := a.userSaver.SaveUser(ctx, email, string(encryptedPassword), username, app_id)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"email":  email,
			"app_id": app_id,
			"error":  err,
		}).Error("failed to save user to database")
		return false, 0, err
	}
	a.log.WithFields(logrus.Fields{
		"user_id":  user_id,
		"email":    email,
		"username": username,
		"app_id":   app_id,
	}).Info("user registered successfully")
	return true, user_id, nil
}

// Logout invalidates a user's refresh token, effectively logging them out
// It verifies the token, extracts user information, and removes the token from storage
func (a *Auth) Logout(ctx context.Context, providedToken string, app_id int64) (bool, error) {
	const op = "auth.Logout"

	app, err := a.appProvider.App(ctx, app_id)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"error":  err,
			"op":     op,
		}).Error("failed to get app from provider")
		return false, fmt.Errorf("%s: %w", op, err)
	}

	token, err := providerjwt.ParseToken(providedToken, app)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"error":  err,
			"op":     op,
		}).Error("invalid token provided for logout")
		return false, fmt.Errorf("%s: invalid token: %w", op, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"op":     op,
		}).Error("invalid token claims in logout")
		return false, fmt.Errorf("%s: invalid token claims", op)
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"op":     op,
		}).Error("invalid user_id in token claims")
		return false, fmt.Errorf("%s: invalid user_id in token", op)
	}
	userID := int64(userIDFloat)

	if err := a.tokenProvider.DeleteToken(ctx, userID); err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
			"error":   err,
		}).Error("failed to delete token from provider")
		return false, fmt.Errorf("%s: %w", op, err)
	}

	a.log.WithFields(logrus.Fields{
		"user_id": userID,
		"app_id":  app_id,
	}).Info("user logged out successfully")
	return true, nil
}

// RefreshToken generates new access and refresh tokens using an existing refresh token
// It validates the provided token, verifies it against the database, and generates new token pair
func (a *Auth) RefreshToken(ctx context.Context, providedToken string, app_id int64) (string, string, error) {
	const op = "auth.RefreshToken"

	app, err := a.appProvider.App(ctx, app_id)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"error":  err,
			"op":     op,
		}).Error("failed to get app from provider")
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := providerjwt.ParseToken(providedToken, app)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"error":  err,
			"op":     op,
		}).Error("invalid token provided for refresh")
		return "", "", fmt.Errorf("%s: invalid token: %w", op, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"op":     op,
		}).Error("invalid token claims in refresh")
		return "", "", fmt.Errorf("%s: invalid token claims", op)
	}

	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		a.log.WithFields(logrus.Fields{
			"app_id": app_id,
			"op":     op,
		}).Error("invalid user_id in token claims")
		return "", "", fmt.Errorf("%s: invalid user_id in token", op)
	}
	userID := int64(userIDFloat)

	if claims["purpose"] != "refresh" {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
		}).Error("invalid token purpose for refresh")
		return "", "", fmt.Errorf("%s: invalid token purpose", op)
	}

	// Compare with token in DB
	dbToken, err := a.tokenProvider.GetToken(ctx, userID)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
			"error":   err,
		}).Error("failed to get token from provider")
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if dbToken == "" || dbToken != providedToken {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
		}).Error("token is revoked or invalid")
		return "", "", fmt.Errorf("%s: token is revoked or invalid", op)
	}

	user, err := a.userProvider.GetUserByID(ctx, userID)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
			"error":   err,
		}).Error("failed to get user by ID")
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	if user == nil {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
		}).Error("user not found for token refresh")
		return "", "", fmt.Errorf("%s: user not found", op)
	}

	// Generate new pair
	accessToken, newRefreshToken, err := providerjwt.GenerateToken(app, user, a.tokenTTL)
	if err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": userID,
			"app_id":  app_id,
			"op":      op,
			"error":   err,
		}).Error("failed to generate new tokens")
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// Update token in DB (Rotation)
	if err := a.tokenSaver.SaveToken(ctx, user.Id, newRefreshToken); err != nil {
		a.log.WithFields(logrus.Fields{
			"user_id": user.Id,
			"app_id":  app_id,
			"op":      op,
			"error":   err,
		}).Error("failed to save new refresh token")
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	a.log.WithFields(logrus.Fields{
		"user_id": userID,
		"app_id":  app_id,
	}).Info("token refreshed successfully")
	return accessToken, newRefreshToken, nil
}
