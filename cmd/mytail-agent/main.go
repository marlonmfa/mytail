package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var version = "dev"

type Config struct {
	ServerURL    string `json:"server_url"`
	MachineToken string `json:"machine_token"`
	Paused       bool   `json:"paused"`
}

type Relay struct {
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
	User       string `json:"user"`
	Transport  string `json:"transport"`
	RemotePort int    `json:"remote_port"`
	KnownHosts string `json:"known_hosts"`
}

type ActiveRequest struct {
	ID              int    `json:"id"`
	OperatorEmail   string `json:"operator_email"`
	Reason          string `json:"reason"`
	ApprovedMinutes int    `json:"approved_minutes"`
	ExpiresAt       int64  `json:"expires_at"`
	OperatorSSHKey  string `json:"operator_ssh_public_key"`
	RemoteUser      string `json:"remote_user"`
	Relay           Relay  `json:"relay"`
}

type Checkin struct {
	Machine struct {
		CustomerName string `json:"customer_name"`
		MachineName  string `json:"machine_name"`
		ConsentCode  string `json:"consent_code"`
	} `json:"machine"`
	ActiveRequest *ActiveRequest `json:"active_request"`
	ServerTime    int64          `json:"server_time"`
}

type Agent struct {
	mu           sync.RWMutex
	configPath   string
	config       Config
	last         *Checkin
	lastCheckin  time.Time
	lastError    string
	client       *http.Client
	tunnel       *exec.Cmd
	tunnelFor    int
	connectivity Connectivity
	sshServer    *embeddedSSHServer
}

type Connectivity struct {
	Control, RelayTCP, RelaySSH, LocalSSH string
	CheckedAt                             time.Time
}

func configPath() string {
	if value := os.Getenv("MYTAIL_CONFIG"); value != "" {
		return value
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "MyTail", "config.json")
	case "darwin":
		return "/Library/Application Support/MyTail/config.json"
	default:
		return "/etc/mytail/config.json"
	}
}

func (a *Agent) load() error {
	data, err := os.ReadFile(a.configPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	a.config = cfg
	return nil
}

func validateConfig(cfg Config) error {
	u, err := url.Parse(strings.TrimSpace(cfg.ServerURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("informe uma URL HTTP ou HTTPS válida")
	}
	if u.Scheme != "https" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" {
		return errors.New("servidores remotos precisam usar HTTPS")
	}
	if len(strings.TrimSpace(cfg.MachineToken)) < 16 {
		return errors.New("o token da máquina parece inválido")
	}
	return nil
}

func (a *Agent) save(cfg Config) error {
	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	cfg.MachineToken = strings.TrimSpace(cfg.MachineToken)
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.configPath), 0700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(a.configPath, data, 0600); err != nil {
		return err
	}
	a.mu.Lock()
	a.config = cfg
	a.last = nil
	a.lastError = ""
	a.mu.Unlock()
	return nil
}

func (a *Agent) deviceKeyPath() string {
	return filepath.Join(filepath.Dir(a.configPath), "device_ed25519")
}
func (a *Agent) knownHostsPath() string {
	return filepath.Join(filepath.Dir(a.configPath), "relay_known_hosts")
}

func cloudflaredPath() (string, error) {
	name := "cloudflared"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if executable, err := os.Executable(); err == nil {
		bundled := filepath.Join(filepath.Dir(executable), name)
		if info, statErr := os.Stat(bundled); statErr == nil && !info.IsDir() {
			return bundled, nil
		}
	}
	if found, err := exec.LookPath(name); err == nil {
		return found, nil
	}
	return "", errors.New("conector Cloudflare não encontrado")
}

func (a *Agent) ensureDeviceKey() (string, error) {
	privateKey := a.deviceKeyPath()
	publicKey := privateKey + ".pub"
	if data, err := os.ReadFile(publicKey); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	if err := os.MkdirAll(filepath.Dir(privateKey), 0700); err != nil {
		return "", err
	}
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "mytail-device", "-f", privateKey)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("ssh-keygen: %v: %s", err, strings.TrimSpace(string(output)))
	}
	_ = os.Chmod(privateKey, 0600)
	data, err := os.ReadFile(publicKey)
	return strings.TrimSpace(string(data)), err
}

func platformName() string { return runtime.GOOS + "/" + runtime.GOARCH }

type embeddedSSHServer struct {
	mu          sync.RWMutex
	listener    net.Listener
	signer      ssh.Signer
	operatorKey ssh.PublicKey
	expiresAt   int64
	agent       *Agent
}

func (a *Agent) ensureEmbeddedSSHServer() error {
	a.mu.RLock()
	existing := a.sshServer
	a.mu.RUnlock()
	if existing != nil {
		return nil
	}
	keyPath := filepath.Join(filepath.Dir(a.configPath), "embedded_ssh_host.pem")
	var privateKey ed25519.PrivateKey
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return errors.New("chave do SSH local inválida")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		privateKey, ok = parsed.(ed25519.PrivateKey)
		if !ok {
			return errors.New("tipo de chave SSH local inválido")
		}
	} else {
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privateKey = generated
		encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
			return err
		}
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:22222")
	if err != nil {
		return fmt.Errorf("porta SSH local 22222: %w", err)
	}
	server := &embeddedSSHServer{listener: listener, signer: signer, agent: a}
	a.mu.Lock()
	if a.sshServer != nil {
		a.mu.Unlock()
		_ = listener.Close()
		return nil
	}
	a.sshServer = server
	a.mu.Unlock()
	go server.serve()
	return nil
}

func parseAuthorizedKey(value string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(value)))
	return key, err
}

func (s *embeddedSSHServer) authorize(publicKey string, expiresAt int64) error {
	key, err := parseAuthorizedKey(publicKey)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.operatorKey = key
	s.expiresAt = expiresAt
	s.mu.Unlock()
	return nil
}

func (s *embeddedSSHServer) revoke() {
	s.mu.Lock()
	s.operatorKey = nil
	s.expiresAt = 0
	s.mu.Unlock()
}

func (s *embeddedSSHServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *embeddedSSHServer) handle(raw net.Conn) {
	config := &ssh.ServerConfig{PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.mu.RLock()
		allowed, expires := s.operatorKey, s.expiresAt
		s.mu.RUnlock()
		if metadata.User() != "mytail-admin" || allowed == nil || time.Now().Unix() >= expires || !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, errors.New("sessão MyTail não autorizada")
		}
		return nil, nil
	}}
	config.AddHostKey(s.signer)
	connection, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		_ = raw.Close()
		return
	}
	s.agent.reportEvent("ssh.session.started", map[string]string{"source": connection.RemoteAddr().String()})
	defer func() {
		s.agent.reportEvent("ssh.session.ended", map[string]string{"source": connection.RemoteAddr().String()})
		connection.Close()
	}()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "somente sessões shell são permitidas")
			continue
		}
		stream, reqs, err := channel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(stream, reqs)
	}
}

func sshPayloadString(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	length := int(binary.BigEndian.Uint32(payload[:4]))
	if length < 0 || length > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+length])
}

func (s *embeddedSSHServer) handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	for request := range requests {
		switch request.Type {
		case "pty-req":
			request.Reply(false, nil)
		case "shell":
			request.Reply(true, nil)
			s.runCommand(channel, "")
			return
		case "exec":
			command := sshPayloadString(request.Payload)
			request.Reply(command != "", nil)
			if command != "" {
				s.runCommand(channel, command)
			}
			return
		default:
			request.Reply(false, nil)
		}
	}
}

func (s *embeddedSSHServer) runCommand(channel ssh.Channel, command string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if command == "" {
			cmd = exec.Command("powershell.exe", "-NoLogo", "-NoProfile")
		} else {
			cmd = exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-Command", command)
		}
	} else if command == "" {
		cmd = exec.Command("/bin/sh", "-l")
	} else {
		cmd = exec.Command("/bin/sh", "-lc", command)
	}
	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	err := cmd.Run()
	status := uint32(0)
	if err != nil {
		status = 1
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, status)
	_, _ = channel.SendRequest("exit-status", false, payload)
}

func (a *Agent) checkin() error {
	a.mu.RLock()
	cfg := a.config
	a.mu.RUnlock()
	if cfg.Paused {
		return nil
	}
	if cfg.ServerURL == "" || cfg.MachineToken == "" {
		return errors.New("agente ainda não configurado")
	}
	publicKey, err := a.ensureDeviceKey()
	if err != nil {
		return err
	}
	if err := a.ensureEmbeddedSSHServer(); err != nil {
		return err
	}
	a.mu.RLock()
	localServer := a.sshServer
	a.mu.RUnlock()
	if localServer == nil {
		return errors.New("servidor SSH local indisponível")
	}
	localHostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(localServer.signer.PublicKey())))
	hostname, _ := os.Hostname()
	payload, _ := json.Marshal(map[string]string{
		"machine_token": cfg.MachineToken, "hostname": hostname, "ssh_public_key": publicKey,
		"local_ssh_host_key": localHostKey, "remote_user": "mytail-admin", "platform": platformName(),
	})
	req, err := http.NewRequest(http.MethodPost, cfg.ServerURL+"/api/agent/checkin", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MyTail-Agent/"+version)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("servidor respondeu HTTP %d", resp.StatusCode)
	}
	var result Checkin
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	a.mu.Lock()
	a.last = &result
	a.lastCheckin = time.Now()
	a.lastError = ""
	a.mu.Unlock()
	a.reconcileSession(&result, cfg)
	return nil
}

func (a *Agent) poll() {
	for {
		err := a.checkin()
		a.mu.Lock()
		if err != nil {
			a.lastError = err.Error()
		}
		a.mu.Unlock()
		if err != nil {
			a.stopSession()
		}
		time.Sleep(5 * time.Second)
	}
}

func (a *Agent) stopSession() {
	a.mu.Lock()
	cmd := a.tunnel
	a.tunnel = nil
	a.tunnelFor = 0
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	a.mu.RLock()
	server := a.sshServer
	a.mu.RUnlock()
	if server != nil {
		server.revoke()
	}
}

func (a *Agent) reconcileSession(result *Checkin, cfg Config) {
	active := result.ActiveRequest
	if cfg.Paused || active == nil || active.ExpiresAt <= time.Now().Unix() || active.OperatorSSHKey == "" {
		a.stopSession()
		return
	}
	a.mu.RLock()
	sameTunnel := a.tunnel != nil && a.tunnel.Process != nil && a.tunnelFor == active.ID
	a.mu.RUnlock()
	if sameTunnel {
		return
	}
	a.stopSession()
	if err := a.ensureEmbeddedSSHServer(); err != nil {
		a.mu.Lock()
		a.lastError = "servidor SSH local: " + err.Error()
		a.mu.Unlock()
		return
	}
	a.mu.RLock()
	server := a.sshServer
	a.mu.RUnlock()
	if server == nil {
		return
	}
	if err := server.authorize(active.OperatorSSHKey, active.ExpiresAt); err != nil {
		a.mu.Lock()
		a.lastError = "chave SSH temporária: " + err.Error()
		a.mu.Unlock()
		return
	}
	if err := a.startTunnel(active); err != nil {
		server.revoke()
		a.mu.Lock()
		a.lastError = "túnel SSH: " + err.Error()
		a.mu.Unlock()
	}
}

func (a *Agent) sshArgs(relay Relay, reverse bool) ([]string, error) {
	if relay.Host == "" || relay.User == "" || relay.SSHPort < 1 || relay.RemotePort < 1024 || relay.KnownHosts == "" {
		return nil, errors.New("configuração do relay incompleta")
	}
	if err := os.WriteFile(a.knownHostsPath(), []byte(strings.TrimSpace(relay.KnownHosts)+"\n"), 0600); err != nil {
		return nil, err
	}
	args := []string{
		"-i", a.deviceKeyPath(), "-p", strconv.Itoa(relay.SSHPort),
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ExitOnForwardFailure=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + a.knownHostsPath(),
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-N",
	}
	if relay.Transport == "cloudflare" {
		connector, err := cloudflaredPath()
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(connector, " \t") {
			connector = `"` + connector + `"`
		}
		args = append(args, "-o", "ProxyCommand="+connector+" access ssh --hostname %h")
	} else if relay.Transport != "" && relay.Transport != "direct" {
		return nil, fmt.Errorf("transporte de relay desconhecido: %s", relay.Transport)
	}
	if reverse {
		args = append(args, "-R", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:22222", relay.RemotePort))
	}
	args = append(args, relay.User+"@"+relay.Host)
	return args, nil
}

func (a *Agent) startTunnel(active *ActiveRequest) error {
	args, err := a.sshArgs(active.Relay, true)
	if err != nil {
		return err
	}
	cmd := exec.Command("ssh", args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(900 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return errors.New("o processo SSH terminou durante a conexão")
	}
	a.mu.Lock()
	a.tunnel = cmd
	a.tunnelFor = active.ID
	a.mu.Unlock()
	a.reportEvent("tunnel.started", map[string]string{"request_id": strconv.Itoa(active.ID), "relay_port": strconv.Itoa(active.Relay.RemotePort)})
	go func(requestID int) {
		err := cmd.Wait()
		a.reportEvent("tunnel.stopped", map[string]string{"request_id": strconv.Itoa(requestID)})
		a.mu.Lock()
		if a.tunnel == cmd {
			a.tunnel = nil
			a.tunnelFor = 0
			if err != nil {
				a.lastError = "túnel encerrado: " + err.Error()
			}
		}
		a.mu.Unlock()
	}(active.ID)
	return nil
}

func (a *Agent) postJSON(path string, payload any, target any) error {
	a.mu.RLock()
	cfg := a.config
	a.mu.RUnlock()
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, cfg.ServerURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if target == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

func (a *Agent) reportEvent(eventType string, details map[string]string) {
	a.mu.RLock()
	token := a.config.MachineToken
	a.mu.RUnlock()
	if token == "" {
		return
	}
	go func() {
		_ = a.postJSON("/api/agent/event", map[string]any{"machine_token": token, "event_type": eventType, "details": details}, nil)
	}()
}

func (a *Agent) testConnectivity() Connectivity {
	a.mu.RLock()
	cfg := a.config
	a.mu.RUnlock()
	result := Connectivity{Control: "falhou", RelayTCP: "não testado", RelaySSH: "não testado", LocalSSH: "falhou", CheckedAt: time.Now()}
	if err := a.ensureEmbeddedSSHServer(); err == nil {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:22222", 3*time.Second)
		if err == nil {
			result.LocalSSH = "ok"
			_ = conn.Close()
		}
	}
	publicKey, err := a.ensureDeviceKey()
	if err != nil {
		result.Control = err.Error()
		return result
	}
	if err := a.checkin(); err != nil {
		result.Control = err.Error()
		return result
	}
	var bootstrap struct {
		ControlPlane string `json:"control_plane"`
		Relay        Relay  `json:"relay"`
	}
	err = a.postJSON("/api/agent/connectivity", map[string]string{"machine_token": cfg.MachineToken, "ssh_public_key": publicKey}, &bootstrap)
	if err != nil {
		result.Control = err.Error()
		return result
	}
	result.Control = "ok"
	if bootstrap.Relay.Transport == "cloudflare" {
		if _, err := cloudflaredPath(); err != nil {
			result.RelayTCP = err.Error()
			return result
		}
		result.RelayTCP = "ok (HTTPS/Cloudflare)"
	} else {
		address := net.JoinHostPort(bootstrap.Relay.Host, strconv.Itoa(bootstrap.Relay.SSHPort))
		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			result.RelayTCP = err.Error()
			return result
		}
		result.RelayTCP = "ok"
		_ = conn.Close()
	}
	args, err := a.sshArgs(bootstrap.Relay, false)
	if err != nil {
		result.RelaySSH = err.Error()
		return result
	}
	cmd := exec.Command("ssh", args...)
	if err := cmd.Start(); err != nil {
		result.RelaySSH = err.Error()
		return result
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			result.RelaySSH = err.Error()
		} else {
			result.RelaySSH = "ok"
		}
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		result.RelaySSH = "ok"
	}
	a.reportEvent("connectivity.tested", map[string]string{"control": result.Control, "relay_tcp": result.RelayTCP, "relay_ssh": result.RelaySSH, "local_ssh": result.LocalSSH})
	return result
}

type View struct {
	Version, Error, ServerURL, Customer, Machine, Code, Operator, Reason, State string
	ControlTest, RelayTCPTest, RelaySSHTest, LocalSSHTest, CheckedAt            string
	Configured, Active, Paused                                                  bool
	TunnelActive                                                                bool
	Expires                                                                     string
}

func (a *Agent) view() View {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v := View{Version: version, Error: a.lastError, ServerURL: a.config.ServerURL, Configured: a.config.ServerURL != "" && a.config.MachineToken != "", State: "Sem acesso ativo"}
	v.TunnelActive = a.tunnel != nil && a.tunnel.Process != nil
	v.ControlTest, v.RelayTCPTest, v.RelaySSHTest, v.LocalSSHTest = a.connectivity.Control, a.connectivity.RelayTCP, a.connectivity.RelaySSH, a.connectivity.LocalSSH
	if !a.connectivity.CheckedAt.IsZero() {
		v.CheckedAt = a.connectivity.CheckedAt.Format("02/01/2006 15:04:05")
	}
	v.Paused = a.config.Paused
	if v.Paused {
		v.State = "Agente pausado"
	}
	if a.last != nil {
		v.Customer, v.Machine, v.Code = a.last.Machine.CustomerName, a.last.Machine.MachineName, a.last.Machine.ConsentCode
		if !v.Paused && a.last.ActiveRequest != nil && a.last.ActiveRequest.ExpiresAt > time.Now().Unix() {
			v.Active = true
			v.State = "Acesso autorizado"
			v.Operator = a.last.ActiveRequest.OperatorEmail
			v.Reason = a.last.ActiveRequest.Reason
			v.Expires = time.Unix(a.last.ActiveRequest.ExpiresAt, 0).Format("02/01/2006 15:04:05")
		}
	}
	return v
}

var page = template.Must(template.New("page").Parse(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10"><title>MyTail</title><style>
:root{color-scheme:dark;--a:#57e6b1;--bg:#07111f;--p:#102137;--m:#aab6ca}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#f5f8ff;font:16px/1.55 system-ui,sans-serif}.w{width:min(760px,calc(100% - 32px));margin:55px auto}.brand{font-size:20px;font-weight:800}.dot{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--a);box-shadow:0 0 15px var(--a);margin-right:10px}.card{background:var(--p);border:1px solid #ffffff1f;border-radius:20px;padding:26px;margin-top:20px}.state{font-size:32px;font-weight:800;margin:4px 0 12px}.active{border-color:#57e6b166}.muted{color:var(--m)}dl{display:grid;grid-template-columns:150px 1fr;gap:8px}dt{color:var(--m)}dd{margin:0;overflow-wrap:anywhere}input{width:100%;padding:12px;margin:6px 0 14px;border:1px solid #ffffff25;border-radius:10px;background:#07111f;color:white}button{padding:12px 18px;border:0;border-radius:10px;background:var(--a);color:#052119;font-weight:800}.warn{color:#ffca73}@media(max-width:560px){dl{grid-template-columns:1fr;gap:2px}dd{margin-bottom:9px}}</style></head><body><main class="w"><div class="brand"><span class="dot"></span>MyTail <span class="muted">v{{.Version}}</span></div>
{{if .Configured}}<section class="card {{if .Active}}active{{end}}"><div class="muted">STATUS LOCAL</div><div class="state">{{.State}}</div>{{if .Error}}<p class="warn">{{.Error}}</p>{{end}}<dl><dt>Cliente</dt><dd>{{.Customer}}</dd><dt>Máquina</dt><dd>{{.Machine}}</dd><dt>Código de consentimento</dt><dd><strong>{{.Code}}</strong></dd><dt>Servidor</dt><dd>{{.ServerURL}}</dd><dt>Nível da sessão</dt><dd>privilégios do serviço MyTail (administrador)</dd><dt>Túnel reverso</dt><dd>{{if .TunnelActive}}ativo{{else}}inativo{{end}}</dd>{{if .Active}}<dt>Operador</dt><dd>{{.Operator}}</dd><dt>Motivo</dt><dd>{{.Reason}}</dd><dt>Expira</dt><dd>{{.Expires}}</dd>{{end}}</dl><form method="post" action="/pause"><button type="submit">{{if .Paused}}Retomar agente{{else}}Pausar agente{{end}}</button></form></section>{{end}}
{{if .CheckedAt}}<section class="card"><h2>Teste de conectividade</h2><dl><dt>Controle HTTPS</dt><dd>{{.ControlTest}}</dd><dt>Relay TCP</dt><dd>{{.RelayTCPTest}}</dd><dt>Autenticação SSH</dt><dd>{{.RelaySSHTest}}</dd><dt>SSH local</dt><dd>{{.LocalSSHTest}}</dd><dt>Testado em</dt><dd>{{.CheckedAt}}</dd></dl></section>{{end}}
<section class="card"><h2>Configuração e teste</h2><p class="muted">O MyTail gera uma chave exclusiva deste dispositivo. A chave pública do operador fica somente em memória durante uma autorização aprovada; a sessão recebe os privilégios administrativos do serviço.</p><form method="post" action="/setup"><label>URL HTTPS do servidor<input name="server_url" value="{{.ServerURL}}" placeholder="https://broker-suporte.hirableaiagents.com" required></label><label>Token de inscrição da máquina<input name="machine_token" type="password" placeholder="Token fornecido pelo suporte" required></label><button type="submit">Salvar e testar HTTPS, relay e SSH</button></form></section></main></body></html>`))

func (a *Agent) handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	_ = page.Execute(w, a.view())
}

func (a *Agent) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método inválido", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "origem inválida", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "formulário inválido", 400)
		return
	}
	cfg := Config{ServerURL: r.FormValue("server_url"), MachineToken: r.FormValue("machine_token")}
	if err := a.save(cfg); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	connectivity := a.testConnectivity()
	a.mu.Lock()
	a.connectivity = connectivity
	a.mu.Unlock()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Host == "127.0.0.1:8787" || u.Host == "localhost:8787")
}

func (a *Agent) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método inválido", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "origem inválida", http.StatusForbidden)
		return
	}
	a.mu.RLock()
	cfg := a.config
	a.mu.RUnlock()
	cfg.Paused = !cfg.Paused
	if err := a.save(cfg); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func openBrowser(target string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	_ = command.Start()
}

func main() {
	open := false
	testOnly := false
	configureServer, configureToken := "", ""
	for index := 1; index < len(os.Args); index++ {
		switch os.Args[index] {
		case "--open":
			open = true
		case "--test-only":
			testOnly = true
		case "--configure-server":
			if index+1 < len(os.Args) {
				index++
				configureServer = os.Args[index]
			}
		case "--machine-token":
			if index+1 < len(os.Args) {
				index++
				configureToken = os.Args[index]
			}
		}
	}
	agent := &Agent{configPath: configPath(), client: &http.Client{Timeout: 10 * time.Second}}
	if err := agent.load(); err != nil {
		log.Printf("configuração: %v", err)
	}
	if configureServer != "" || configureToken != "" {
		if err := agent.save(Config{ServerURL: configureServer, MachineToken: configureToken}); err != nil {
			log.Print(err)
			os.Exit(2)
		}
	}
	if testOnly {
		result := agent.testConnectivity()
		encoded, _ := json.Marshal(result)
		fmt.Println(string(encoded))
		if result.Control != "ok" || result.RelayTCP != "ok" || result.RelaySSH != "ok" || result.LocalSSH != "ok" {
			os.Exit(3)
		}
		return
	}
	go agent.poll()
	mux := http.NewServeMux()
	mux.HandleFunc("/", agent.handleHome)
	mux.HandleFunc("/setup", agent.handleSetup)
	mux.HandleFunc("/pause", agent.handlePause)
	server := &http.Server{Addr: "127.0.0.1:8787", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if open {
		go func() { time.Sleep(500 * time.Millisecond); openBrowser("http://127.0.0.1:8787") }()
	}
	log.Printf("MyTail %s disponível em http://127.0.0.1:8787", version)
	log.Fatal(server.ListenAndServe())
}
