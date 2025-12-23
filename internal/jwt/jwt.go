package jwt

import (
	"fmt"
	"ssoq/internal/model"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(app *model.App, user *model.User, tokenTTL time.Duration) (string, string, error) {
	if app == nil {
		return "", "", fmt.Errorf("app is nil")
	}
	if user == nil {
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
		return "", "", err
	}

	refreshToken, err := refresh_token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
func ParseToken(token string, app *model.App) (*jwt.Token, error) {
	if app == nil {
		return nil, fmt.Errorf("app is nil")
	}
	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(app.Secret), nil
	})
}
