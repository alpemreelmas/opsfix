package ssh

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type sshClient struct {
	client *ssh.Client
}

func dial(host string, port int, user, keyPath, knownHostsFile string, connectTimeout time.Duration) (Client, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("ssh: read key %q: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse private key: %w", err)
	}

	var hostKeyCallback ssh.HostKeyCallback
	if knownHostsFile != "" {
		hostKeyCallback, err = knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("ssh: load known_hosts %q: %w", knownHostsFile, err)
		}
	} else {
		// Dev mode: skip host key verification
		hostKeyCallback = ssh.InsecureIgnoreHostKey() //nolint:gosec
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         connectTimeout,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh: handshake %s: %w", addr, err)
	}

	return &sshClient{client: ssh.NewClient(c, chans, reqs)}, nil
}

func (c *sshClient) Exec(cmd string) (ExecResult, error) {
	start := time.Now()

	sess, err := c.client.NewSession()
	if err != nil {
		return ExecResult{}, fmt.Errorf("ssh: new session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	exitCode := 0
	if err := sess.Run(cmd); err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			return ExecResult{}, fmt.Errorf("ssh: run %q: %w", cmd, err)
		}
	}

	return ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Duration: time.Since(start),
	}, nil
}

func (c *sshClient) Close() error {
	return c.client.Close()
}
