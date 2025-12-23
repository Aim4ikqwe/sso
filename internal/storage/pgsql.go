package storage

import (
	"context"
	"database/sql"
	"fmt"
	"ssoq/internal/model"

	_ "github.com/lib/pq"
)

type Storage struct {
	db *sql.DB
}

func NewDB(connection string) (*Storage, error) {
	db, err := sql.Open("postgres", connection)
	if err != nil {
		return nil, fmt.Errorf("storage.NewDB: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("storage.NewDB ping: %w", err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

// SaveUser saves a new user to the database.
func (s *Storage) SaveUser(ctx context.Context, email string, password string, username string, app_id int64) (int64, error) {
	const op = "storage.pgsql.SaveUser"

	var id int64
	query := `INSERT INTO users (email, pass_hash, username, app_id) VALUES ($1, $2, $3, $4) RETURNING id`
	err := s.db.QueryRowContext(ctx, query, email, password, username, app_id).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// GetUser returns a user by email.
func (s *Storage) GetUser(ctx context.Context, email string) (*model.User, error) {
	const op = "storage.pgsql.GetUser"

	var user model.User
	var passHash string
	query := `SELECT id, email, pass_hash, username, app_id FROM users WHERE email = $1`
	err := s.db.QueryRowContext(ctx, query, email).Scan(&user.Id, &user.Email, &passHash, &user.Username, &user.AppId)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Or return a custom error like storage.ErrUserNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	user.Password = []byte(passHash)

	return &user, nil
}

// App returns an app by id.
func (s *Storage) App(ctx context.Context, app_id int64) (*model.App, error) {
	const op = "storage.pgsql.App"

	var app model.App
	query := `SELECT id, name, secret FROM apps WHERE id = $1`
	err := s.db.QueryRowContext(ctx, query, app_id).Scan(&app.Id, &app.Name, &app.Secret)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: app not found", op)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &app, nil
}

// SaveToken saves a refresh token for a user.
// It updates the token if a session already exists for the user.
func (s *Storage) SaveToken(ctx context.Context, user_id int64, token string) error {
	const op = "storage.pgsql.SaveToken"

	query := `INSERT INTO sessions (user_id, refresh_token) VALUES ($1, $2)
              ON CONFLICT (user_id) DO UPDATE SET refresh_token = EXCLUDED.refresh_token`

	_, err := s.db.ExecContext(ctx, query, user_id, token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// DeleteToken deletes a refresh token for a user (logout).
func (s *Storage) DeleteToken(ctx context.Context, user_id int64) error {
	const op = "storage.pgsql.DeleteToken"

	query := `DELETE FROM sessions WHERE user_id = $1`

	_, err := s.db.ExecContext(ctx, query, user_id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// GetToken returns the refresh token for a user.
func (s *Storage) GetToken(ctx context.Context, user_id int64) (string, error) {
	const op = "storage.pgsql.GetToken"

	var token string
	query := `SELECT refresh_token FROM sessions WHERE user_id = $1`
	err := s.db.QueryRowContext(ctx, query, user_id).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // Or return a custom error
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// GetUserByID returns a user by their ID.
func (s *Storage) GetUserByID(ctx context.Context, id int64) (*model.User, error) {
	const op = "storage.pgsql.GetUserByID"

	var user model.User
	var passHash string
	query := `SELECT id, email, pass_hash, username, app_id FROM users WHERE id = $1`
	err := s.db.QueryRowContext(ctx, query, id).Scan(&user.Id, &user.Email, &passHash, &user.Username, &user.AppId)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	user.Password = []byte(passHash)

	return &user, nil
}
