package jwt

import (
	"fmt"
	"ssoq/internal/model"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// log is a logger instance for the jwt package
var log *logrus.Logger

// SetLogger sets the logger instance for the jwt package
func SetLogger(logger *logrus.Logger) {
	log = logger
}

// GenerateToken generates access and refresh tokens for a user and app
// It creates JWT tokens with appropriate expiration times and purposes
func GenerateToken(app *model.App, user *model.User, tokenTTL time.Duration) (string, string, error) {
	if app == nil {
		log.Error("app is nil in GenerateToken")
		return "", "", fmt.Errorf("app is nil")
	}
	if user == nil {
		log.Error("user is nil in GenerateToken")
		return "", "", fmt.Errorf("user is nil")
	}
	access_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.Id,
		"username": user.Username,
		"email":    user.Email,
		"app_id":   app.Id,
		"exp":      time.Now().Add(tokenTTL).Unix(),
		"purpose":  "access",
	})
	refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.Id,
		"username": user.Username,
		"email":    user.Email,
		"app_id":   app.Id,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"purpose":  "refresh",
	})
	accessToken, err := access_token.SignedString([]byte(app.Secret))
	if err != nil {
		log.WithFields(logrus.Fields{
			"user_id": user.Id,
			"app_id":  app.Id,
			"error":   err,
		}).Error("failed to sign access token")
		return "", "", err
	}

	refreshToken, err := refresh_token.SignedString([]byte(app.Secret))
	if err != nil {
		log.WithFields(logrus.Fields{
			"user_id": user.Id,
			"app_id":  app.Id,
			"error":   err,
		}).Error("failed to sign refresh token")
		return "", "", err
	}

	log.WithFields(logrus.Fields{
		"user_id": user.Id,
		"app_id":  app.Id,
		"purpose": "access",
	}).Debug("access token generated")
	log.WithFields(logrus.Fields{
		"user_id": user.Id,
		"app_id":  app.Id,
		"purpose": "refresh",
	}).Debug("refresh token generated")

	return accessToken, refreshToken, nil
}

// ParseToken parses and validates a JWT token using the app's secret key
func ParseToken(token string, app *model.App) (*jwt.Token, error) {
	if app == nil {
		log.Error("app is nil in ParseToken")
		return nil, fmt.Errorf("app is nil")
	}
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(app.Secret), nil
	})
}
