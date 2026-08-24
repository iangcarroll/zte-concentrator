package concentrator

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iangcarroll/zte-coord/icg"
)

// startObs brings up a concentrator plus its observability server on ephemeral
// ports and returns the base URL and key.
func startObs(t *testing.T, key string) (*harness, string, string) {
	t.Helper()
	h := startHarness(t, nil)
	obs, err := NewHTTP(h.srv, HTTPConfig{Addr: "127.0.0.1:0", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if obs == nil {
		t.Fatal("NewHTTP returned nil for a non-empty address")
	}
	done := make(chan error, 1)
	go func() { done <- obs.Serve() }()
	t.Cleanup(func() {
		obs.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("observability server did not stop")
		}
	})
	select {
	case <-obs.Ready():
	case err := <-done:
		t.Fatalf("observability server did not bind: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("observability server did not bind")
	}
	return h, "http://" + obs.Addr(), obs.GeneratedKey()
}

func get(t *testing.T, url string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// The API guards operational state on a box whose ICG ports are, by design,
// exposed. Every accepted credential form and every rejection matters.
func TestObservabilityAuth(t *testing.T) {
	_, base, key := startObs(t, "")
	if key == "" {
		t.Fatal("no key was generated")
	}

	t.Run("no credential", func(t *testing.T) {
		if code, _ := get(t, base+"/api/status", nil); code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", code)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		code, _ := get(t, base+"/api/status", map[string]string{"X-Icgd-Key": "nope"})
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", code)
		}
	})
	t.Run("prefix of the real key", func(t *testing.T) {
		// Guards against a length-only or prefix comparison.
		code, _ := get(t, base+"/api/status", map[string]string{"X-Icgd-Key": key[:len(key)-1]})
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", code)
		}
	})
	t.Run("header", func(t *testing.T) {
		if code, _ := get(t, base+"/api/status", map[string]string{"X-Icgd-Key": key}); code != 200 {
			t.Fatalf("status = %d, want 200", code)
		}
	})
	t.Run("bearer", func(t *testing.T) {
		code, _ := get(t, base+"/api/status", map[string]string{"Authorization": "Bearer " + key})
		if code != 200 {
			t.Fatalf("status = %d, want 200", code)
		}
	})
	t.Run("query parameter", func(t *testing.T) {
		if code, _ := get(t, base+"/api/status?key="+key, nil); code != 200 {
			t.Fatalf("status = %d, want 200", code)
		}
	})
	t.Run("the UI shell needs no key", func(t *testing.T) {
		code, body := get(t, base+"/", nil)
		if code != 200 {
			t.Fatalf("status = %d, want 200", code)
		}
		// It must carry no data — only the shell that then asks for a key.
		if !strings.Contains(body, "<title>icgd</title>") {
			t.Error("the UI page does not look like the UI page")
		}
		if strings.Contains(body, key) {
			t.Fatal("the UI page leaked the API key")
		}
	})
	t.Run("unknown path", func(t *testing.T) {
		if code, _ := get(t, base+"/nope", nil); code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", code)
		}
	})
}

func TestObservabilityUsesConfiguredKey(t *testing.T) {
	_, base, generated := startObs(t, "s3cret")
	if generated != "s3cret" {
		t.Fatalf("GeneratedKey = %q, want the configured key", generated)
	}
	if code, _ := get(t, base+"/api/status", map[string]string{"X-Icgd-Key": "s3cret"}); code != 200 {
		t.Fatalf("status = %d", code)
	}
}

func TestHTTPDisabledByEmptyAddr(t *testing.T) {
	h := startHarness(t, nil)
	obs, err := NewHTTP(h.srv, HTTPConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if obs != nil {
		t.Fatal("an empty Addr must disable the observability server entirely")
	}
}

// The snapshot is what the whole UI is built on, so it has to reflect a real
// session rather than a hopeful zero value.
func TestSnapshotReflectsALiveSession(t *testing.T) {
	h, base, key := startObs(t, "")
	l := h.dialTCPLeg()
	l.handshake()

	var snap ServerSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := get(t, base+"/api/status", map[string]string{"X-Icgd-Key": key})
		if code != 200 {
			t.Fatalf("status = %d", code)
		}
		if err := json.Unmarshal([]byte(body), &snap); err != nil {
			t.Fatalf("api/status is not valid JSON: %v", err)
		}
		if len(snap.Sessions) == 1 && snap.Sessions[0].State == "ICG_AND_SRV_BOTH_OK" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session never appeared in the snapshot: %+v", snap.Sessions)
		}
		time.Sleep(50 * time.Millisecond)
	}

	s := snap.Sessions[0]
	if s.IcgID != "172.16.25.18" {
		t.Errorf("IcgID = %q", s.IcgID)
	}
	if !s.Admitted {
		t.Error("session should be admitted with no allowlist configured")
	}
	if s.ClientMAC != "de:ad:be:ef:00:01" {
		t.Errorf("ClientMAC = %q, want the MAC from the handshake", s.ClientMAC)
	}
	if len(s.Legs) != 1 || s.Legs[0].Kind != "tcp" {
		t.Errorf("Legs = %+v, want one tcp leg", s.Legs)
	}
	if s.Counters.Handshakes == 0 {
		t.Error("Handshakes counter was not reported")
	}
	if snap.Listeners.TCP == "" {
		t.Error("Listeners.TCP was not reported")
	}
	if snap.Magic != "0x12345678" {
		t.Errorf("Magic = %q", snap.Magic)
	}
}

// A refused device must be visible with the MAC in the fix text, because that
// string is what the operator pastes into -devices.
func TestRefusalAppearsInNotices(t *testing.T) {
	h := startHarness(t, func(c *Config) {
		c.AllowedDevices = map[string]bool{"aa:bb:cc:dd:ee:ff": true}
	})
	l := h.dialTCPLeg()
	body := make([]byte, icg.HandshakeReqLen)
	copy(body, []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}) // a MAC not on the list
	l.send(&icg.Frame{Type: icg.TypeHandshake, Opcode: icg.HSReqWithConfig, Body: body})

	deadline := time.Now().Add(5 * time.Second)
	for {
		ns := h.srv.Notices()
		for _, n := range ns {
			if n.Kind == "device-refused" {
				if !strings.Contains(n.Fix, "de:ad:be:ef:00:01") {
					t.Errorf("the fix should name the MAC to allowlist, got %q", n.Fix)
				}
				if !strings.Contains(n.Msg, "not in the allowlist") {
					t.Errorf("Msg = %q", n.Msg)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no device-refused notice appeared; notices = %+v", ns)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Repeats collapse, so a device stuck in its 1 Hz retry loop (or a scanner)
// cannot push everything else out of the ring.
func TestNoticesCollapseRepeats(t *testing.T) {
	var n noticeLog
	for i := 0; i < 500; i++ {
		n.add(Notice{Kind: "magic-mismatch", Peer: "1.2.3.4:5", Msg: "same"})
	}
	got := n.snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 collapsed entry", len(got))
	}
	if got[0].Count != 500 {
		t.Errorf("Count = %d, want 500", got[0].Count)
	}
}

func TestNoticesRingIsBounded(t *testing.T) {
	var n noticeLog
	for i := 0; i < maxNotices*3; i++ {
		n.add(Notice{Kind: "k", Peer: "p", Msg: strings.Repeat("x", i%97) + string(rune('a'+i%26))})
	}
	got := n.snapshot()
	if len(got) > maxNotices {
		t.Fatalf("ring holds %d, cap is %d", len(got), maxNotices)
	}
	// Newest first, so the operator reads the top.
	if len(got) > 1 && got[0].At.Before(got[len(got)-1].At) {
		t.Error("notices are not newest-first")
	}
}
