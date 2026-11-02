package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/anacrolix/torrent/storage"
)

func TestParseRate(t *testing.T) {
	for input, want := range map[string]int64{"100K": 102400, "1M": 1048576, "0": 0} {
		got, err := parseRate(input)
		if err != nil || got != want {
			t.Fatalf("parseRate(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
}

func TestRPCRejectsInvalidSecret(t *testing.T) {
	d := &daemon{secret: "correct"}
	body := `{"jsonrpc":"2.0","id":"test","method":"aria2.getVersion","params":["token:wrong"]}`
	req := httptest.NewRequest(http.MethodPost, "/jsonrpc", strings.NewReader(body))
	response := httptest.NewRecorder()
	d.serveRPC(response, req)
	var decoded rpcResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Error == nil || decoded.Error.Message != "token RPC inválido" {
		t.Fatalf("resposta inesperada: %s", response.Body.String())
	}
}

func TestVersionAdvertisesHolePunching(t *testing.T) {
	d := &daemon{secret: "correct"}
	body := `{"jsonrpc":"2.0","id":"test","method":"aria2.getVersion","params":["token:correct"]}`
	req := httptest.NewRequest(http.MethodPost, "/jsonrpc", strings.NewReader(body))
	response := httptest.NewRecorder()
	d.serveRPC(response, req)
	if !strings.Contains(response.Body.String(), "BEP55") {
		t.Fatalf("BEP55 ausente: %s", response.Body.String())
	}
}

func TestNetworkStatsAreAvailableWithoutTorrents(t *testing.T) {
	client := newTestClient(t, t.TempDir())
	defer client.Close()
	d := &daemon{client: client, secret: "correct", items: map[string]*transfer{}, byHash: map[string]string{}}
	body := `{"jsonrpc":"2.0","id":"test","method":"kmp.getNetworkStats","params":["token:correct"]}`
	req := httptest.NewRequest(http.MethodPost, "/jsonrpc", strings.NewReader(body))
	response := httptest.NewRecorder()
	d.serveRPC(response, req)
	if !strings.Contains(response.Body.String(), "successfulAfterHolepunchConnect") {
		t.Fatalf("telemetria ausente: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "peerDiscovery") {
		t.Fatalf("telemetria de descoberta ausente: %s", response.Body.String())
	}
}

func newTestClient(t *testing.T, dir string) *torrent.Client {
	t.Helper()
	cfg := torrent.NewDefaultClientConfig()
	cfg.DataDir = dir
	cfg.ListenPort = 0
	cfg.NoDHT = true
	cfg.DisableTrackers = true
	cfg.NoDefaultPortForwarding = true
	cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{ClientBaseDir: dir})
	client, err := torrent.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCompletionWaitsForPartFilePromotion(t *testing.T) {
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("KMP part file\n"), 1024)
	source := filepath.Join(t.TempDir(), "package.zip")
	if err := os.WriteFile(source, payload, 0644); err != nil {
		t.Fatal(err)
	}
	info := metainfo.Info{PieceLength: 16 * 1024}
	if err := info.BuildFromFilePath(source); err != nil {
		t.Fatal(err)
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, dir)
	defer client.Close()
	added, err := client.AddTorrent(&metainfo.MetaInfo{InfoBytes: infoBytes})
	if err != nil {
		t.Fatal(err)
	}
	x := &transfer{Dir: dir, Torrent: added}
	partial := filepath.Join(dir, "package.zip.part")
	if err := os.WriteFile(partial, payload, 0644); err != nil {
		t.Fatal(err)
	}
	if filesInPlace(x) {
		t.Fatal("arquivo .part tratado como concluído")
	}
	if err := os.Rename(partial, filepath.Join(dir, "package.zip")); err != nil {
		t.Fatal(err)
	}
	if !filesInPlace(x) {
		t.Fatal("arquivo final com tamanho correto não reconhecido")
	}
}

func TestTransferBetweenTwoDaemons(t *testing.T) {
	root := t.TempDir()
	seedDir, downloadDir := filepath.Join(root, "seed"), filepath.Join(root, "download")
	if err := os.MkdirAll(seedDir, 0755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("KMP distributed transfer\n"), 4096)
	packagePath := filepath.Join(seedDir, "package.zip")
	if err := os.WriteFile(packagePath, payload, 0644); err != nil {
		t.Fatal(err)
	}
	info := metainfo.Info{PieceLength: 16 * 1024}
	if err := info.BuildFromFilePath(packagePath); err != nil {
		t.Fatal(err)
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	mi := metainfo.MetaInfo{InfoBytes: infoBytes}
	mi.SetDefaults()
	var torrentBytes bytes.Buffer
	if err := mi.Write(&torrentBytes); err != nil {
		t.Fatal(err)
	}

	newClient := func(port int, dir string) *torrent.Client {
		cfg := torrent.NewDefaultClientConfig()
		cfg.DataDir, cfg.ListenPort, cfg.Seed = dir, port, true
		cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{ClientBaseDir: dir})
		cfg.NoDHT, cfg.DisableTrackers, cfg.NoDefaultPortForwarding = true, true, true
		client, err := torrent.NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	seedClient := newClient(49131, seedDir)
	defer seedClient.Close()
	leecherClient := newClient(49132, downloadDir)
	defer leecherClient.Close()
	seed := &daemon{client: seedClient, stateDir: filepath.Join(root, "seed-state"), baseDir: seedDir, items: map[string]*transfer{}, byHash: map[string]string{}}
	leecher := &daemon{client: leecherClient, stateDir: filepath.Join(root, "leech-state"), baseDir: downloadDir, items: map[string]*transfer{}, byHash: map[string]string{}}
	if err := os.MkdirAll(seed.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(leecher.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.addMetainfo(torrentBytes.Bytes(), map[string]string{"dir": seedDir}, false); err != nil {
		t.Fatal(err)
	}
	magnet := mi.Magnet(nil, &info).String() + "&x.pe=127.0.0.1%3A49131"
	gid, err := leecher.addMagnet(magnet, map[string]string{"dir": downloadDir}, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		status, err := leecher.status(gid)
		if err != nil {
			t.Fatal(err)
		}
		if status["dir"] != downloadDir {
			t.Fatalf("diretório RPC = %v; esperado %s", status["dir"], downloadDir)
		}
		if status["completedLength"] == status["totalLength"] && status["totalLength"] != "0" {
			if _, err := os.Stat(filepath.Join(downloadDir, "package.zip.part")); err == nil && status["status"] == "complete" {
				t.Fatal("status complete enquanto o arquivo ainda é .part")
			}
		}
		if status["status"] == "complete" {
			if status["seeder"] != "true" {
				t.Fatalf("complete sem seeder: %#v", status)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("transferência não terminou: %#v", status)
		case <-time.After(100 * time.Millisecond):
		}
	}
	downloaded, err := os.ReadFile(filepath.Join(downloadDir, "package.zip"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(downloaded, payload) {
		t.Fatal("conteúdo transferido difere do original")
	}
}

func TestAddPeersConnectsAnExistingTorrent(t *testing.T) {
	root := t.TempDir()
	seedDir, downloadDir := filepath.Join(root, "seed"), filepath.Join(root, "download")
	if err := os.MkdirAll(seedDir, 0755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("KMP add peers\n"), 4096)
	if err := os.WriteFile(filepath.Join(seedDir, "package.zip"), payload, 0644); err != nil {
		t.Fatal(err)
	}
	info := metainfo.Info{PieceLength: 16 * 1024}
	if err := info.BuildFromFilePath(filepath.Join(seedDir, "package.zip")); err != nil {
		t.Fatal(err)
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var torrentBytes bytes.Buffer
	if err := (&metainfo.MetaInfo{InfoBytes: infoBytes}).Write(&torrentBytes); err != nil {
		t.Fatal(err)
	}
	newDaemon := func(port int, dir string) *daemon {
		cfg := torrent.NewDefaultClientConfig()
		cfg.DataDir, cfg.ListenPort, cfg.Seed = dir, port, true
		cfg.DefaultStorage = storage.NewFileOpts(storage.NewFileClientOpts{ClientBaseDir: dir})
		cfg.NoDHT, cfg.DisableTrackers, cfg.NoDefaultPortForwarding = true, true, true
		client, err := torrent.NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		stateDir := filepath.Join(root, filepath.Base(dir)+"-state")
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			t.Fatal(err)
		}
		return &daemon{client: client, stateDir: stateDir, baseDir: dir, items: map[string]*transfer{}, byHash: map[string]string{}}
	}
	seed, leecher := newDaemon(49133, seedDir), newDaemon(49134, downloadDir)
	if _, err := seed.addMetainfo(torrentBytes.Bytes(), map[string]string{"dir": seedDir}, false); err != nil {
		t.Fatal(err)
	}
	gid, err := leecher.addMetainfo(torrentBytes.Bytes(), map[string]string{"dir": downloadDir}, false)
	if err != nil {
		t.Fatal(err)
	}
	invalid, _ := json.Marshal([]string{"não-é-endereço"})
	if _, err := leecher.call("kmp.addPeers", []json.RawMessage{json.RawMessage(`"` + gid + `"`), invalid}); err == nil {
		t.Fatal("peer inválido aceito")
	}
	peers, _ := json.Marshal([]string{"127.0.0.1:49133"})
	if _, err := leecher.call("kmp.addPeers", []json.RawMessage{json.RawMessage(`"` + gid + `"`), peers}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		status, err := leecher.status(gid)
		if err != nil {
			t.Fatal(err)
		}
		if status["status"] == "complete" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("o peer adicionado não entregou o torrent: %#v", status)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
