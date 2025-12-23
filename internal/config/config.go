package config

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env      string        `toml:"env" env-default:"local"`
	TokenTTL time.Duration `toml:"tokenTTL" env-required:"true"`
	Grpc     GrpcConfig    `toml:"grpc"`
	Db       DbConfig      `toml:"db"`
}

type GrpcConfig struct {
	Port    int           `toml:"port" env-required:"true"`
	Timeout time.Duration `toml:"timeout" env-required:"true"`
}

type DbConfig struct {
	Host    string `toml:"host" env-required:"true"`
	Port    int    `toml:"port" env-required:"true"`
	User    string `toml:"user" env-required:"true"`
	Pass    string `toml:"pass" env-required:"true"`
	Dbname  string `toml:"dbname" env-required:"true"`
	Sslmode string `toml:"sslmode" env-default:"disable"`
}

func fetchConfig() string {
	var res string
	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()
	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}
	if res == "" {
		res = "D:\\golangprojects\\ssoq\\config\\config.toml"
	}
	return res
}
func MustLoad() *Config {
	configPath := fetchConfig()
	if configPath == "" {
		panic("config path not found")
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist")
	}
	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("cannot read config: " + err.Error())
	}
	return &cfg

}
func (c *Config) ConnectionString() string {
	connectionString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Db.Host, c.Db.Port, c.Db.User, c.Db.Pass, c.Db.Dbname, c.Db.Sslmode)
	return connectionString
}
