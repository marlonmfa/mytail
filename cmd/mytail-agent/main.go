package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var version = "dev"

type Config struct {
	ServerURL    string `json:"server_url"`
	MachineToken string `json:"machine_token"`
	Paused       bool   `json:"paused"`
}

type ActiveRequest struct {
	ID              int    `json:"id"`
	OperatorEmail   string `json:"operator_email"`
	Reason          string `json:"reason"`
	ApprovedMinutes int    `json:"approved_minutes"`
	ExpiresAt       int64  `json:"expires_at"`
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
	mu          sync.RWMutex
	configPath  string
	config      Config
	last        *Checkin
	lastCheckin time.Time
	lastError   string
	client      *http.Client
}

func configPath() string {
	if value := os.Getenv("MYTAIL_CONFIG"); value != "" {
		return value
	}
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = os.TempDir()
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
	hostname, _ := os.Hostname()
	payload, _ := json.Marshal(map[string]string{"machine_token": cfg.MachineToken, "hostname": hostname})
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
		time.Sleep(15 * time.Second)
	}
}

type View struct {
	Version, Error, ServerURL, Customer, Machine, Code, Operator, Reason, State string
	Configured, Active, Paused                                                  bool
	Expires                                                                     string
}

func (a *Agent) view() View {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v := View{Version: version, Error: a.lastError, ServerURL: a.config.ServerURL, Configured: a.config.ServerURL != "" && a.config.MachineToken != "", State: "Sem acesso ativo"}
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
{{if .Configured}}<section class="card {{if .Active}}active{{end}}"><div class="muted">STATUS LOCAL</div><div class="state">{{.State}}</div>{{if .Error}}<p class="warn">{{.Error}}</p>{{end}}<dl><dt>Cliente</dt><dd>{{.Customer}}</dd><dt>Máquina</dt><dd>{{.Machine}}</dd><dt>Código de consentimento</dt><dd><strong>{{.Code}}</strong></dd><dt>Servidor</dt><dd>{{.ServerURL}}</dd>{{if .Active}}<dt>Operador</dt><dd>{{.Operator}}</dd><dt>Motivo</dt><dd>{{.Reason}}</dd><dt>Expira</dt><dd>{{.Expires}}</dd>{{end}}</dl><form method="post" action="/pause"><button type="submit">{{if .Paused}}Retomar agente{{else}}Pausar agente{{end}}</button></form></section>{{end}}
<section class="card"><h2>Configuração do agente</h2><p class="muted">O MyTail envia identificação da máquina e status ao servidor informado. Esta versão não executa comandos nem cria túneis.</p><form method="post" action="/setup"><label>URL HTTPS do servidor<input name="server_url" value="{{.ServerURL}}" placeholder="https://servidor.exemplo.com" required></label><label>Token de inscrição da máquina<input name="machine_token" type="password" placeholder="Token fornecido pelo suporte" required></label><button type="submit">Salvar e conectar</button></form></section></main></body></html>`))

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
	_ = a.checkin()
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
	for _, arg := range os.Args[1:] {
		if arg == "--open" {
			open = true
		}
	}
	agent := &Agent{configPath: configPath(), client: &http.Client{Timeout: 10 * time.Second}}
	if err := agent.load(); err != nil {
		log.Printf("configuração: %v", err)
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
