package server

import (
	"path/filepath"
	"testing"

	"github.com/charmbracelet/charm/client"
	"github.com/charmbracelet/keygen"
)

func TestSSHAuthMiddleware(t *testing.T) {
	cfg := DefaultConfig()
	td := t.TempDir()
	cfg.DataDir = filepath.Join(td, ".data")
	sp := filepath.Join(td, ".ssh")
	kp, err := keygen.NewWithWrite(sp, "charm_server", []byte(""), keygen.Ed25519)
	if err != nil {
		t.Fatalf("keygen error: %s", err)
	}
	cfg = cfg.WithKeys(kp.PublicKey, kp.PrivateKeyPEM)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server error: %s", err)
	}

	go s.Start()
	t.Run("api-auth", func(t *testing.T) {
		ccfg, err := client.ConfigFromEnv()
		if err != nil {
			t.Fatalf("client config from env error: %s", err)
		}
		ccfg.Host = cfg.Host
		ccfg.SSHPort = cfg.SSHPort
		ccfg.HTTPPort = cfg.HTTPPort
		cl, err := client.NewClient(ccfg)
		if err != nil {
			t.Fatalf("new client error: %s", err)
		}
		auth, err := cl.Auth()
		if err != nil {
			t.Fatalf("auth error: %s", err)
		}
		if auth.JWT == "" {
			t.Fatal("auth error, missing JWT")
		}
		if auth.ID == "" {
			t.Fatal("auth error, missing ID")
		}
		if auth.PublicKey == "" {
			t.Fatal("auth error, missing PublicKey")
		}
		// if len(auth.EncryptKeys) == 0 {
		// 	t.Fatal("auth error, missing EncryptKeys")
		// }
	})
	errs := make(chan error, 1)
	go func() {
		t.Run("server close", func(t *testing.T) {
			err := s.Close()
			errs <- err
		})
	}()
	err = <-errs
	if err != nil {
		t.Fatalf("error shutting down: %s", err)
	}
}
