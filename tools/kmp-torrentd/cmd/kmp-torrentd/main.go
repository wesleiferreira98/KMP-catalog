package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
	"golang.org/x/time/rate"
)

const version = "0.2.3"

type rpcRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type savedTorrent struct {
	GID      string `json:"gid"`
	Dir      string `json:"dir"`
	Magnet   string `json:"magnet,omitempty"`
	Metainfo string `json:"metainfo,omitempty"`
	Paused   bool   `json:"paused,omitempty"`
}

type transfer struct {
	GID      string
	Dir      string
	Magnet   string
	Metainfo []byte
	Torrent  *torrent.Torrent
	Paused   bool
	AddedAt  time.Time
	mu       sync.Mutex
	lastAt   time.Time
	lastDown int64
	lastUp   int64
	downRate int64
	upRate   int64
}

type daemon struct {
	client                *torrent.Client
	secret                string
	stateDir              string
	baseDir               string
	mu                    sync.RWMutex
	items                 map[string]*transfer
	byHash                map[string]string
	shutdown              context.CancelFunc
}

func main() {
	var rpcAddr, secret, stateDir, dataDir, uploadLimit, downloadLimit string
	var listenPort, connsPerTorrent, halfOpenPerTorrent int
	flag.StringVar(&rpcAddr, "rpc-listen", "127.0.0.1:26801", "endereço local da API JSON-RPC")
	flag.StringVar(&secret, "rpc-secret", "", "segredo da API JSON-RPC")
	flag.StringVar(&stateDir, "state-dir", "./state", "diretório de estado")
	flag.StringVar(&dataDir, "data-dir", "./downloads", "diretório padrão dos downloads")
	flag.IntVar(&listenPort, "listen-port", 6881, "porta TCP/UDP do BitTorrent")
	flag.StringVar(&uploadLimit, "upload-limit", "100K", "limite global de upload")
	flag.StringVar(&downloadLimit, "download-limit", "0", "limite global de download")
	// Handheld kernels and Wi-Fi drivers degrade sharply with dozens of parallel
	// dials, so the defaults stay small. A public node raises them: it can only
	// rendezvous (BEP 55) peers that are connected to it at the same time.
	flag.IntVar(&connsPerTorrent, "max-conns-per-torrent", 12, "conexões estabelecidas por torrent")
	flag.IntVar(&halfOpenPerTorrent, "half-open-per-torrent", 4, "tentativas de conexão simultâneas por torrent")
	flag.Parse()
	if secret == "" {
		log.Fatal("--rpc-secret é obrigatório")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatal(err)
	}

	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = dataDir
	cfg.ListenPort = listenPort
	cfg.Seed = true
	cfg.DisableIPv4 = false
	cfg.DisableIPv6 = false
	cfg.DisableTCP = false
	cfg.DisableUTP = false
	cfg.DisablePEX = false
	cfg.NoDHT = false
	cfg.NoDefaultPortForwarding = false
	cfg.PeriodicallyAnnounceTorrentsToDht = true
	cfg.EstablishedConnsPerTorrent = connsPerTorrent
	cfg.HalfOpenConnsPerTorrent = halfOpenPerTorrent
	cfg.ExtendedHandshakeClientVersion = "KMP torrentd/" + version
	cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{ClientBaseDir: dataDir})
	if n, err := parseRate(uploadLimit); err == nil && n > 0 {
		cfg.UploadRateLimiter = rate.NewLimiter(rate.Limit(n), max(int(n), 32*1024))
	}
	if n, err := parseRate(downloadLimit); err == nil && n > 0 {
		cfg.DownloadRateLimiter = rate.NewLimiter(rate.Limit(n), max(int(n), 1024*1024))
	}
	client, err := torrent.NewClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	d := &daemon{client: client, secret: secret, stateDir: stateDir, baseDir: dataDir,
		items: map[string]*transfer{}, byHash: map[string]string{}, shutdown: cancel}
	if err := d.restore(); err != nil {
		log.Printf("restauração parcial: %v", err)
	}
	go d.sampleRates(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/jsonrpc", d.serveRPC)
	server := &http.Server{Addr: rpcAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", rpcAddr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		cancel()
	}()
	log.Printf("kmp-torrentd %s RPC em http://%s/jsonrpc, BitTorrent TCP/UDP %d", version, rpcAddr, listenPort)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	_ = d.persist()
}

func (d *daemon) serveRPC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "POST obrigatório", http.StatusMethodNotAllowed)
		return
	}
	var req rpcRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	if err := dec.Decode(&req); err != nil {
		d.writeError(w, req.ID, -32700, "JSON inválido")
		return
	}
	params := req.Params
	if len(params) == 0 {
		d.writeError(w, req.ID, 1, "token RPC ausente")
		return
	}
	var token string
	if err := json.Unmarshal(params[0], &token); err != nil || token != "token:"+d.secret {
		d.writeError(w, req.ID, 1, "token RPC inválido")
		return
	}
	result, err := d.call(req.Method, params[1:])
	if err != nil {
		d.writeError(w, req.ID, 1, err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
}

func (d *daemon) writeError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}})
}

func (d *daemon) call(method string, p []json.RawMessage) (any, error) {
	switch method {
	case "aria2.addTorrent":
		if len(p) < 1 {
			return nil, errors.New("torrent ausente")
		}
		var encoded string
		if err := json.Unmarshal(p[0], &encoded); err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("torrent base64 inválido: %w", err)
		}
		return d.addMetainfo(raw, optionsAt(p, 2), false)
	case "aria2.addUri":
		if len(p) < 1 {
			return nil, errors.New("URI ausente")
		}
		var uris []string
		if err := json.Unmarshal(p[0], &uris); err != nil || len(uris) == 0 {
			return nil, errors.New("URI inválida")
		}
		return d.addMagnet(uris[0], optionsAt(p, 1), false)
	case "aria2.tellStatus":
		gid, err := stringAt(p, 0)
		if err != nil {
			return nil, err
		}
		return d.status(gid)
	case "aria2.tellActive":
		return d.list("active"), nil
	case "aria2.tellWaiting":
		return d.list("waiting"), nil
	case "aria2.tellStopped":
		return d.list("stopped"), nil
	case "aria2.forcePause":
		gid, err := stringAt(p, 0)
		if err != nil {
			return nil, err
		}
		return "OK", d.pause(gid, true)
	case "aria2.unpause":
		gid, err := stringAt(p, 0)
		if err != nil {
			return nil, err
		}
		return "OK", d.pause(gid, false)
	case "aria2.forceRemove":
		gid, err := stringAt(p, 0)
		if err != nil {
			return nil, err
		}
		return "OK", d.remove(gid)
	case "aria2.removeDownloadResult":
		return "OK", nil
	case "aria2.saveSession":
		return "OK", d.persist()
	case "aria2.getPeers":
		gid, err := stringAt(p, 0)
		if err != nil {
			return nil, err
		}
		return d.peers(gid)
	case "aria2.getGlobalStat":
		return d.globalStat(), nil
	case "aria2.getVersion":
		return map[string]any{"version": "kmp-torrentd " + version, "enabledFeatures": []string{"BitTorrent", "DHT", "IPv6", "PEX", "uTP", "BEP55"}}, nil
	case "kmp.getNetworkStats":
		return d.networkStats(), nil
	case "aria2.shutdown":
		go d.shutdown()
		return "OK", nil
	default:
		return nil, fmt.Errorf("método não implementado: %s", method)
	}
}

func optionsAt(p []json.RawMessage, i int) map[string]string {
	ret := map[string]string{}
	if i < len(p) {
		_ = json.Unmarshal(p[i], &ret)
	}
	return ret
}

func stringAt(p []json.RawMessage, i int) (string, error) {
	if i >= len(p) {
		return "", errors.New("parâmetro ausente")
	}
	var s string
	if err := json.Unmarshal(p[i], &s); err != nil {
		return "", err
	}
	return s, nil
}

func (d *daemon) addMetainfo(raw []byte, opts map[string]string, restoring bool) (string, error) {
	mi, err := metainfo.Load(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("torrent inválido: %w", err)
	}
	spec, err := torrent.TorrentSpecFromMetaInfoErr(mi)
	if err != nil {
		return "", err
	}
	dir := chooseDir(opts["dir"], d.baseDir)
	spec.Storage = storage.NewFileOpts(storage.NewFileClientOpts{ClientBaseDir: dir})
	t, _, err := d.client.AddTorrentSpec(spec)
	if err != nil {
		return "", err
	}
	return d.register(t, dir, "", raw, restoring)
}

func (d *daemon) addMagnet(uri string, opts map[string]string, restoring bool) (string, error) {
	spec, err := torrent.TorrentSpecFromMagnetUri(uri)
	if err != nil {
		return "", fmt.Errorf("magnet inválido: %w", err)
	}
	dir := chooseDir(opts["dir"], d.baseDir)
	spec.Storage = storage.NewFileOpts(storage.NewFileClientOpts{ClientBaseDir: dir})
	t, _, err := d.client.AddTorrentSpec(spec)
	if err != nil {
		return "", err
	}
	return d.register(t, dir, uri, nil, restoring)
}

func (d *daemon) register(t *torrent.Torrent, dir, magnet string, raw []byte, restoring bool) (string, error) {
	hash := strings.ToLower(t.InfoHash().HexString())
	d.mu.Lock()
	if gid := d.byHash[hash]; gid != "" {
		d.mu.Unlock()
		return gid, nil
	}
	sum := sha256.Sum256([]byte(hash))
	gid := hex.EncodeToString(sum[:])[:16]
	x := &transfer{GID: gid, Dir: dir, Magnet: magnet, Metainfo: raw, Torrent: t, AddedAt: time.Now(), lastAt: time.Now()}
	d.items[gid], d.byHash[hash] = x, gid
	d.mu.Unlock()
	if t.Info() != nil {
		t.DownloadAll()
	} else {
		go func() {
			<-t.GotInfo()
			t.DownloadAll()
		}()
	}
	if !restoring {
		_ = d.persist()
	}
	return gid, nil
}

func (d *daemon) status(gid string) (map[string]any, error) {
	x := d.get(gid)
	if x == nil {
		return nil, errors.New("GID não encontrado")
	}
	return d.statusOf(x), nil
}

func (d *daemon) statusOf(x *transfer) map[string]any {
	t := x.Torrent
	total, done := t.Length(), t.BytesCompleted()
	finished := total > 0 && done >= total && filesInPlace(x)
	st := t.Stats()
	status := "active"
	if x.Paused {
		status = "paused"
	} else if finished {
		status = "complete"
	}
	x.mu.Lock()
	downRate, upRate := x.downRate, x.upRate
	x.mu.Unlock()
	files := []map[string]any{}
	if t.Info() != nil {
		for _, f := range t.Files() {
			files = append(files, map[string]any{"index": strconv.Itoa(len(files) + 1), "path": filepath.Join(x.Dir, filepath.FromSlash(f.Path())), "length": strconv.FormatInt(f.Length(), 10), "completedLength": strconv.FormatInt(f.BytesCompleted(), 10), "selected": "true", "uris": []any{}})
		}
	}
	return map[string]any{
		"gid": x.GID, "status": status, "totalLength": strconv.FormatInt(total, 10),
		"dir":             x.Dir,
		"completedLength": strconv.FormatInt(done, 10), "downloadSpeed": strconv.FormatInt(downRate, 10),
		"downloadLength": strconv.FormatInt(st.BytesReadUsefulData.Int64(), 10),
		"uploadSpeed": strconv.FormatInt(upRate, 10), "uploadLength": strconv.FormatInt(st.BytesWrittenData.Int64(), 10),
		"infoHash": strings.ToLower(t.InfoHash().HexString()), "seeder": strconv.FormatBool(finished),
		"numSeeders": strconv.Itoa(st.ConnectedSeeders), "connections": strconv.Itoa(st.ActivePeers), "files": files,
	}
}

// A storage de arquivos grava em "<nome>.part" e só renomeia depois de verificar a
// última peça, então BytesCompleted pode atingir o total antes de o arquivo final existir.
func filesInPlace(x *transfer) bool {
	if x.Torrent.Info() == nil {
		return false
	}
	for _, f := range x.Torrent.Files() {
		stat, err := os.Stat(filepath.Join(x.Dir, filepath.FromSlash(f.Path())))
		if err != nil || !stat.Mode().IsRegular() || stat.Size() != f.Length() {
			return false
		}
	}
	return true
}

func (d *daemon) list(kind string) []map[string]any {
	d.mu.RLock()
	values := make([]*transfer, 0, len(d.items))
	for _, x := range d.items {
		values = append(values, x)
	}
	d.mu.RUnlock()
	ret := []map[string]any{}
	for _, x := range values {
		s := d.statusOf(x)
		status := s["status"].(string)
		if (kind == "active" && (status == "active" || status == "complete")) || (kind == "waiting" && status == "paused") {
			ret = append(ret, s)
		}
	}
	return ret
}

func (d *daemon) get(gid string) *transfer { d.mu.RLock(); defer d.mu.RUnlock(); return d.items[gid] }

func (d *daemon) pause(gid string, paused bool) error {
	x := d.get(gid)
	if x == nil {
		return errors.New("GID não encontrado")
	}
	x.Paused = paused
	if paused {
		x.Torrent.DisallowDataDownload()
		x.Torrent.DisallowDataUpload()
	} else {
		x.Torrent.AllowDataDownload()
		x.Torrent.AllowDataUpload()
		x.Torrent.DownloadAll()
	}
	return d.persist()
}

func (d *daemon) remove(gid string) error {
	d.mu.Lock()
	x := d.items[gid]
	if x == nil {
		d.mu.Unlock()
		return errors.New("GID não encontrado")
	}
	delete(d.items, gid)
	delete(d.byHash, strings.ToLower(x.Torrent.InfoHash().HexString()))
	d.mu.Unlock()
	x.Torrent.Drop()
	return d.persist()
}

func (d *daemon) peers(gid string) ([]map[string]any, error) {
	x := d.get(gid)
	if x == nil {
		return nil, errors.New("GID não encontrado")
	}
	ret := []map[string]any{}
	for _, p := range x.Torrent.PeerConns() {
		addr := ""
		if p.RemoteAddr != nil {
			addr = p.RemoteAddr.String()
		}
		host, port, _ := net.SplitHostPort(addr)
		ret = append(ret, map[string]any{"peerId": hex.EncodeToString(p.PeerID[:]), "ip": host,
			"port": port, "source": string(p.Discovery)})
	}
	return ret, nil
}

func (d *daemon) globalStat() map[string]string {
	var down, up int64
	active, waiting := 0, 0
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, x := range d.items {
		x.mu.Lock()
		down += x.downRate
		up += x.upRate
		x.mu.Unlock()
		if x.Paused {
			waiting++
		} else {
			active++
		}
	}
	return map[string]string{"downloadSpeed": strconv.FormatInt(down, 10), "uploadSpeed": strconv.FormatInt(up, 10), "numActive": strconv.Itoa(active), "numWaiting": strconv.Itoa(waiting), "numStopped": "0", "numStoppedTotal": "0"}
}

func (d *daemon) networkStats() map[string]any {
	stats := d.client.Stats()
	torrents := make([]map[string]any, 0)
	d.mu.RLock()
	values := make([]*transfer, 0, len(d.items))
	for _, x := range d.items {
		values = append(values, x)
	}
	d.mu.RUnlock()
	for _, x := range values {
		sources := map[string]int{}
		for _, peer := range x.Torrent.KnownSwarm() {
			sources[string(peer.Source)]++
		}
		holepunchCapable := 0
		connections := x.Torrent.PeerConns()
		for _, peer := range connections {
			if _, ok := peer.PeerExtensionIDs["ut_holepunch"]; ok {
				holepunchCapable++
			}
		}
		torrents = append(torrents, map[string]any{
			"gid":                   x.GID,
			"infoHash":              strings.ToLower(x.Torrent.InfoHash().HexString()),
			"knownPeers":            len(x.Torrent.KnownSwarm()),
			"connectedPeers":        len(connections),
			"holepunchCapablePeers": holepunchCapable,
			"peerSources":           sources,
		})
	}
	return map[string]any{
		"activeHalfOpenAttempts":          stats.ActiveHalfOpenAttempts,
		"undialableWithoutHolepunch":      stats.NumPeersUndialableWithoutHolepunch,
		"dialedAfterHolepunchConnect":     stats.NumPeersUndialableWithoutHolepunchDialedAfterHolepunchConnect,
		"dialableOnlyAfterHolepunch":      stats.NumPeersDialableOnlyAfterHolepunch,
		"successfulAfterHolepunchConnect": stats.NumPeersDialedSuccessfullyAfterHolepunchConnect,
		"probablyConnectedByHolepunch":    stats.NumPeersProbablyOnlyConnectedDueToHolepunch,
		"peerDiscovery":                    []string{"trackers", "DHT", "PEX", "LPD"},
		"torrents":                        torrents,
	}
}

func (d *daemon) sampleRates(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			d.mu.RLock()
			values := make([]*transfer, 0, len(d.items))
			for _, x := range d.items {
				values = append(values, x)
			}
			d.mu.RUnlock()
			for _, x := range values {
				st := x.Torrent.Stats()
				down, up := st.BytesReadUsefulData.Int64(), st.BytesWrittenData.Int64()
				x.mu.Lock()
				secs := now.Sub(x.lastAt).Seconds()
				if secs > 0 {
					x.downRate = int64(float64(down-x.lastDown) / secs)
					x.upRate = int64(float64(up-x.lastUp) / secs)
				}
				x.lastAt, x.lastDown, x.lastUp = now, down, up
				x.mu.Unlock()
			}
		}
	}
}

func (d *daemon) persist() error {
	d.mu.RLock()
	saved := make([]savedTorrent, 0, len(d.items))
	for _, x := range d.items {
		saved = append(saved, savedTorrent{GID: x.GID, Dir: x.Dir, Magnet: x.Magnet, Metainfo: base64.StdEncoding.EncodeToString(x.Metainfo), Paused: x.Paused})
	}
	d.mu.RUnlock()
	raw, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(d.stateDir, "session.json.tmp")
	dst := filepath.Join(d.stateDir, "session.json")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func (d *daemon) restore() error {
	raw, err := os.ReadFile(filepath.Join(d.stateDir, "session.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved []savedTorrent
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var errs []string
	for _, s := range saved {
		var gid string
		if s.Metainfo != "" {
			b, err := base64.StdEncoding.DecodeString(s.Metainfo)
			if err == nil {
				gid, err = d.addMetainfo(b, map[string]string{"dir": s.Dir}, true)
			}
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
		} else {
			gid, err = d.addMagnet(s.Magnet, map[string]string{"dir": s.Dir}, true)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
		}
		if s.Paused {
			_ = d.pause(gid, true)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func chooseDir(v, fallback string) string {
	if v == "" {
		return fallback
	}
	if abs, err := filepath.Abs(v); err == nil {
		return abs
	}
	return v
}

func parseRate(v string) (int64, error) {
	v = strings.TrimSpace(strings.ToUpper(v))
	mult := int64(1)
	if strings.HasSuffix(v, "K") {
		mult, v = 1024, strings.TrimSuffix(v, "K")
	} else if strings.HasSuffix(v, "M") {
		mult, v = 1024*1024, strings.TrimSuffix(v, "M")
	} else if strings.HasSuffix(v, "G") {
		mult, v = 1024*1024*1024, strings.TrimSuffix(v, "G")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n * mult, err
}
