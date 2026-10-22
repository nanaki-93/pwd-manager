/*
Copyright © 2025 Marco Andreose <andreose.marco93@gmail.com>
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var nameFlag string

type configContextKey struct{}

// Config holds explicit command configuration without relying on package-level singletons.
type Config struct {
	ConfigFile     string
	ConfigFileUsed string
	Viper          *viper.Viper
	HomeDirFunc    func() (string, error)
	Stderr         io.Writer
}

// NewConfig creates a Config initialized with standard defaults.
func NewConfig(configFile string) *Config {
	return &Config{
		ConfigFile:  configFile,
		Viper:       viper.New(),
		HomeDirFunc: os.UserHomeDir,
		Stderr:      os.Stderr,
	}
}

// WithConfig attaches an explicit Config to the provided context.
func WithConfig(ctx context.Context, cfg *Config) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, configContextKey{}, cfg)
}

// ConfigFromContext retrieves the Config stored in the context, if present.
func ConfigFromContext(ctx context.Context) (*Config, bool) {
	if ctx == nil {
		return nil, false
	}
	cfg, ok := ctx.Value(configContextKey{}).(*Config)
	return cfg, ok
}

// LoadConfig populates the explicit Config structure without abrupt process exits.
func LoadConfig(cfg *Config) error {
	if cfg == nil {
		return errors.New("load config: nil config")
	}
	if cfg.Viper == nil {
		cfg.Viper = viper.New()
	}
	if cfg.HomeDirFunc == nil {
		cfg.HomeDirFunc = os.UserHomeDir
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}

	if cfg.ConfigFile != "" {
		cfg.Viper.SetConfigFile(cfg.ConfigFile)
	} else {
		home, err := cfg.HomeDirFunc()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}

		cfg.Viper.AddConfigPath(home)
		cfg.Viper.SetConfigType("yaml")
		cfg.Viper.SetConfigName(".pwd-manager")
	}

	cfg.Viper.AutomaticEnv()

	if err := cfg.Viper.ReadInConfig(); err != nil {
		var notFoundErr viper.ConfigFileNotFoundError
		if cfg.ConfigFile == "" && errors.As(err, &notFoundErr) {
			return nil
		}
		if cfg.ConfigFile != "" {
			return fmt.Errorf("read config file %q: %w", cfg.ConfigFile, err)
		}
		return fmt.Errorf("read default config: %w", err)
	}

	cfg.ConfigFileUsed = cfg.Viper.ConfigFileUsed()
	if _, err := fmt.Fprintln(cfg.Stderr, "Using config file:", cfg.ConfigFileUsed); err != nil {
		return fmt.Errorf("write config notice: %w", err)
	}
	return nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "pwd-manager",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if _, ok := ConfigFromContext(cmd.Context()); ok {
			return nil
		}
		cfg := NewConfig(cfgFile)
		cfg.Stderr = cmd.ErrOrStderr()
		if err := LoadConfig(cfg); err != nil {
			return err
		}
		cmd.SetContext(WithConfig(cmd.Context(), cfg))
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.pwd-manager.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig loads configuration into a new Config and updates command context without exiting.
func initConfig() {
	cfg := NewConfig(cfgFile)
	cfg.Stderr = rootCmd.ErrOrStderr()
	if err := LoadConfig(cfg); err != nil {
		_, _ = fmt.Fprintln(cfg.Stderr, err)
		return
	}
	rootCmd.SetContext(WithConfig(rootCmd.Context(), cfg))
}
