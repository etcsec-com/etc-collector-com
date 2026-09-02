package saas

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/etcsec-com/etc-collector/internal/logger"
)

func newSigningKeypair(t *testing.T) (priv ed25519.PrivateKey, pubB64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func signCommand(t *testing.T, priv ed25519.PrivateKey, kid, collectorID, commandID, cmdType, expiresAt string, params []byte) *CommandSignature {
	t.Helper()
	signInput, err := buildSignInput(collectorID, commandID, cmdType, expiresAt, params)
	if err != nil {
		t.Fatalf("buildSignInput: %v", err)
	}
	sig := ed25519.Sign(priv, signInput)
	return &CommandSignature{Kid: kid, Sig: base64.StdEncoding.EncodeToString(sig)}
}

func testDaemonForSigning(collectorID string, keys []CommandSigningKey) *Daemon {
	return &Daemon{
		logger: logger.NewNop(),
		creds: &Credentials{
			CollectorID:              collectorID,
			CommandSigningPublicKeys: keys,
		},
	}
}

// TestBuildSignInput_ExactFormat — the wire format is locked (K3, T_045): a
// deterministic byte string, not canonical JSON. Pins the exact bytes so a future edit
// can't silently drift from what TL Cloud signs against.
func TestBuildSignInput_ExactFormat(t *testing.T) {
	params := []byte(`{"a":1}`)
	got, err := buildSignInput("collector-1", "cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "etcsec-cmd-v1\n" +
		"collector-1\n" +
		"cmd-1\n" +
		"UPDATE_CONFIG_AD\n" +
		"2026-08-05T14:00:00Z\n" +
		base64.StdEncoding.EncodeToString(params)
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestBuildSignInput_RejectsLF — every scalar must be refused if it contains a line
// feed BEFORE SIGN_INPUT is built, closing the field-boundary ambiguity the ticket
// calls out explicitly.
func TestBuildSignInput_RejectsLF(t *testing.T) {
	base := []string{"collector-1", "cmd-1", "TYPE", "2026-01-01T00:00:00Z"}
	names := []string{"collectorId", "commandId", "type", "expiresAt"}
	for i, name := range names {
		fields := append([]string(nil), base...)
		fields[i] = fields[i] + "\ninjected"
		if _, err := buildSignInput(fields[0], fields[1], fields[2], fields[3], nil); err == nil {
			t.Fatalf("%s: expected rejection for an embedded LF", name)
		}
	}

	// Sanity: the unmodified base values must NOT be rejected.
	if _, err := buildSignInput(base[0], base[1], base[2], base[3], nil); err != nil {
		t.Fatalf("unexpected rejection of LF-free input: %v", err)
	}
}

func TestResolveSigningKey(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	key := CommandSigningKey{Kid: "k1", PublicKey: "irrelevant"}

	t.Run("found", func(t *testing.T) {
		got, err := resolveSigningKey([]CommandSigningKey{key}, "k1", now)
		if err != nil || got.Kid != "k1" {
			t.Fatalf("got %+v, err=%v", got, err)
		}
	})

	t.Run("unknown kid is an error, not a fallback signal", func(t *testing.T) {
		if _, err := resolveSigningKey([]CommandSigningKey{key}, "does-not-exist", now); err == nil {
			t.Fatal("expected an error for an unresolvable kid")
		}
	})

	t.Run("empty kid rejected", func(t *testing.T) {
		if _, err := resolveSigningKey([]CommandSigningKey{key}, "", now); err == nil {
			t.Fatal("expected an error for an empty kid")
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		future := CommandSigningKey{Kid: "k2", PublicKey: "x", NotBefore: "2027-01-01T00:00:00Z"}
		if _, err := resolveSigningKey([]CommandSigningKey{future}, "k2", now); err == nil {
			t.Fatal("expected an error for a not-yet-valid key")
		}
	})

	t.Run("expired", func(t *testing.T) {
		past := CommandSigningKey{Kid: "k3", PublicKey: "x", NotAfter: "2020-01-01T00:00:00Z"}
		if _, err := resolveSigningKey([]CommandSigningKey{past}, "k3", now); err == nil {
			t.Fatal("expected an error for an expired key")
		}
	})

	t.Run("within window", func(t *testing.T) {
		windowed := CommandSigningKey{Kid: "k4", PublicKey: "x", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}
		if _, err := resolveSigningKey([]CommandSigningKey{windowed}, "k4", now); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

// TestCheckCommandSignature covers every acceptance criterion for the verifier itself.
func TestCheckCommandSignature(t *testing.T) {
	const collectorID = "collector-under-test"
	priv, pubB64 := newSigningKeypair(t)
	key := CommandSigningKey{Kid: "key-1", PublicKey: pubB64}
	baseParams := json.RawMessage(`{"url":"ldaps://dc01.corp.local:636"}`)

	makeSignedCmd := func(commandID, cmdType, expiresAt string, params json.RawMessage, kid, envelopeCollectorID string) Command {
		sig := signCommand(t, priv, kid, envelopeCollectorID, commandID, cmdType, expiresAt, params)
		return Command{
			CommandID:     commandID,
			Type:          cmdType,
			ExpiresAt:     expiresAt,
			CollectorID:   envelopeCollectorID,
			Signature:     sig,
			parametersRaw: params,
		}
	}

	t.Run("valid signature accepted", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "key-1", collectorID)
		if err := d.checkCommandSignature(cmd); err != nil {
			t.Fatalf("expected acceptance, got: %v", err)
		}
	})

	t.Run("tampered payload rejected", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "key-1", collectorID)
		cmd.parametersRaw = json.RawMessage(`{"url":"ldaps://attacker.example:636"}`)
		if err := d.checkCommandSignature(cmd); err == nil {
			t.Fatal("expected rejection for a tampered parameters payload")
		}
	})

	t.Run("unknown kid rejected — not a fallback to unverified", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "attacker-controlled-kid", collectorID)
		if err := d.checkCommandSignature(cmd); err == nil {
			t.Fatal("expected rejection for an unknown kid")
		}
	})

	t.Run("foreign collectorId rejected", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "key-1", "some-other-collector")
		if err := d.checkCommandSignature(cmd); err == nil {
			t.Fatal("expected rejection for a command signed for a different collector")
		}
	})

	t.Run("key outside its notBefore/notAfter window rejected", func(t *testing.T) {
		expired := CommandSigningKey{Kid: "old-key", PublicKey: pubB64, NotAfter: "2020-01-01T00:00:00Z"}
		d := testDaemonForSigning(collectorID, []CommandSigningKey{expired})
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "old-key", collectorID)
		if err := d.checkCommandSignature(cmd); err == nil {
			t.Fatal("expected rejection for a key outside its validity window")
		}
	})

	t.Run("no keys at all falls back to unverified — signed command still runs", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, nil)
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "key-1", collectorID)
		if err := d.checkCommandSignature(cmd); err != nil {
			t.Fatalf("a totally absent key set must fall back to unverified, got: %v", err)
		}
	})

	t.Run("no keys at all falls back to unverified — unsigned command", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, nil)
		cmd := Command{CommandID: "cmd-2", Type: "HEALTH_CHECK", ExpiresAt: "2026-08-05T14:00:00Z", CollectorID: collectorID}
		if err := d.checkCommandSignature(cmd); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("keys installed, unsigned command still accepted and counted (phase 2)", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		cmd := Command{CommandID: "cmd-3", Type: "HEALTH_CHECK", ExpiresAt: "2026-08-05T14:00:00Z", CollectorID: collectorID}
		if err := d.checkCommandSignature(cmd); err != nil {
			t.Fatalf("phase 2 must not reject an unsigned command even with keys installed: %v", err)
		}
		if d.unsignedCommandsAccepted != 1 {
			t.Fatalf("expected unsignedCommandsAccepted=1, got %d", d.unsignedCommandsAccepted)
		}
	})

	t.Run("expiresAt as RFC3339Nano signs and verifies the same as plain RFC3339", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		for _, expiresAt := range []string{
			"2026-08-05T14:00:00Z",
			"2026-08-05T14:00:00.123456789Z",
		} {
			cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", expiresAt, baseParams, "key-1", collectorID)
			if err := d.checkCommandSignature(cmd); err != nil {
				t.Fatalf("expiresAt=%q: expected acceptance, got: %v", expiresAt, err)
			}
		}
	})

	t.Run("last verified kid is recorded", func(t *testing.T) {
		d := testDaemonForSigning(collectorID, []CommandSigningKey{key})
		cmd := makeSignedCmd("cmd-1", "UPDATE_CONFIG_AD", "2026-08-05T14:00:00Z", baseParams, "key-1", collectorID)
		if err := d.checkCommandSignature(cmd); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.lastVerifiedKid != "key-1" {
			t.Fatalf("expected lastVerifiedKid=key-1, got %q", d.lastVerifiedKid)
		}
	})
}

func TestMergeCommandSigningKeys(t *testing.T) {
	dir := t.TempDir()
	d := &Daemon{
		logger:    logger.NewNop(),
		credStore: NewCredentialStore(dir),
		creds:     &Credentials{CollectorID: "c1"},
	}

	t.Run("empty input is a no-op", func(t *testing.T) {
		d.mergeCommandSigningKeys(nil)
		if len(d.creds.CommandSigningPublicKeys) != 0 {
			t.Fatal("expected no change from an empty/absent key set")
		}
	})

	t.Run("first non-empty input is pinned and persists", func(t *testing.T) {
		keys := []CommandSigningKey{{Kid: "k1", PublicKey: "abc"}}
		d.mergeCommandSigningKeys(keys)
		if len(d.creds.CommandSigningPublicKeys) != 1 || d.creds.CommandSigningPublicKeys[0].Kid != "k1" {
			t.Fatalf("keys not stored in memory: %+v", d.creds.CommandSigningPublicKeys)
		}
		reloaded, err := d.credStore.Load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(reloaded.CommandSigningPublicKeys) != 1 || reloaded.CommandSigningPublicKeys[0].Kid != "k1" {
			t.Fatal("keys not persisted to disk — a restart would drop back to unverified")
		}
	})

	// TestMergeCommandSigningKeys/a_later_different_key_set_is_refused,_not_swapped_in
	// — B_141 (T_081), the trust anchor: once a key set is pinned (the previous
	// subtest), a DIFFERENT one arriving later from the exact same channel
	// (PollCommands/health-check responses) must NOT silently replace it. Without
	// this, an attacker able to publish through that channel — e.g. a compromised
	// backend, a threat TLS alone doesn't cover — could mint their own keypair,
	// announce its public half as "the trusted key", and sign malicious commands
	// with it: checkCommandSignature would verify them as genuine.
	t.Run("a later different key set is refused, not swapped in", func(t *testing.T) {
		attackerKeys := []CommandSigningKey{{Kid: "attacker-key", PublicKey: "evil"}}
		d.mergeCommandSigningKeys(attackerKeys)

		if len(d.creds.CommandSigningPublicKeys) != 1 || d.creds.CommandSigningPublicKeys[0].Kid != "k1" {
			t.Fatalf("pinned key set was replaced: %+v", d.creds.CommandSigningPublicKeys)
		}
		reloaded, err := d.credStore.Load()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(reloaded.CommandSigningPublicKeys) != 1 || reloaded.CommandSigningPublicKeys[0].Kid != "k1" {
			t.Fatal("the attacker's key set was persisted to disk — the trust anchor was not pinned")
		}
	})

	t.Run("re-announcing the already-pinned set is still a silent no-op", func(t *testing.T) {
		d.mergeCommandSigningKeys([]CommandSigningKey{{Kid: "k1", PublicKey: "abc"}})
		if len(d.creds.CommandSigningPublicKeys) != 1 || d.creds.CommandSigningPublicKeys[0].Kid != "k1" {
			t.Fatalf("re-announcing the same pinned set must not change anything: %+v", d.creds.CommandSigningPublicKeys)
		}
	})
}

func TestCommandSigningStatus(t *testing.T) {
	d := &Daemon{logger: logger.NewNop(), creds: &Credentials{CollectorID: "c1"}}

	status := d.commandSigningStatus()
	if status.State != commandSigningStateUnverified {
		t.Fatalf("expected %q with no keys installed, got %q", commandSigningStateUnverified, status.State)
	}
	if status.UnsignedAccepted != 0 {
		t.Fatalf("expected UnsignedAccepted=0, got %d", status.UnsignedAccepted)
	}

	d.creds.CommandSigningPublicKeys = []CommandSigningKey{{Kid: "k1", PublicKey: "abc"}}
	status = d.commandSigningStatus()
	if status.State != commandSigningStateVerifying {
		t.Fatalf("expected %q with a key installed, got %q", commandSigningStateVerifying, status.State)
	}

	d.recordUnsignedAccepted(Command{CommandID: "c", Type: "HEALTH_CHECK"})
	status = d.commandSigningStatus()
	if status.UnsignedAccepted != 1 {
		t.Fatalf("expected UnsignedAccepted=1 after one unsigned acceptance, got %d", status.UnsignedAccepted)
	}
}

// TestCommand_UnmarshalJSON_CapturesRawParameters — parametersRaw must be exactly the
// wire bytes of "parameters", byte for byte, alongside the normal Parameters map decode
// every existing dispatch handler relies on.
func TestCommand_UnmarshalJSON_CapturesRawParameters(t *testing.T) {
	raw := []byte(`{
		"commandId": "cmd-1",
		"type": "UPDATE_CONFIG_AD",
		"parameters": {"url":"ldaps://dc01.corp.local:636","nested":{"a":1}},
		"createdAt": "2026-08-05T00:00:00Z",
		"expiresAt": "2026-08-05T14:00:00Z",
		"collectorId": "collector-1",
		"signature": {"kid":"k1","sig":"c2ln"}
	}`)

	var cmd Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if cmd.CommandID != "cmd-1" || cmd.Type != "UPDATE_CONFIG_AD" || cmd.CollectorID != "collector-1" {
		t.Fatalf("basic fields not decoded: %+v", cmd)
	}
	if cmd.Signature == nil || cmd.Signature.Kid != "k1" || cmd.Signature.Sig != "c2ln" {
		t.Fatalf("signature not decoded: %+v", cmd.Signature)
	}
	if cmd.Parameters["url"] != "ldaps://dc01.corp.local:636" {
		t.Fatalf("Parameters map not populated (regression for existing dispatch code): %+v", cmd.Parameters)
	}

	var probe struct {
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("probe unmarshal: %v", err)
	}
	if string(cmd.parametersRaw) != string(probe.Parameters) {
		t.Fatalf("parametersRaw = %s, want %s", cmd.parametersRaw, probe.Parameters)
	}
}

func TestCommand_UnmarshalJSON_NoParameters(t *testing.T) {
	raw := []byte(`{"commandId":"cmd-1","type":"HEALTH_CHECK","expiresAt":"2026-08-05T14:00:00Z"}`)
	var cmd Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cmd.Parameters != nil {
		t.Fatalf("expected nil Parameters, got %+v", cmd.Parameters)
	}
	if cmd.Signature != nil {
		t.Fatal("expected nil Signature")
	}
	if len(cmd.parametersRaw) != 0 {
		t.Fatalf("expected empty parametersRaw, got %q", cmd.parametersRaw)
	}
}

// TestCommandsResponse_UnmarshalPreservesRawParametersPerCommand — the real call path:
// Command's custom UnmarshalJSON must fire for every element decoded inside a slice.
func TestCommandsResponse_UnmarshalPreservesRawParametersPerCommand(t *testing.T) {
	raw := []byte(`{"commands":[
		{"commandId":"a","type":"T","parameters":{"x":1},"expiresAt":"2026-01-01T00:00:00Z"},
		{"commandId":"b","type":"T","parameters":{"y":2},"expiresAt":"2026-01-01T00:00:00Z"}
	],"nextPollAt":"2026-01-01T00:01:00Z"}`)

	var resp CommandsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(resp.Commands))
	}
	if string(resp.Commands[0].parametersRaw) != `{"x":1}` {
		t.Fatalf("command 0 parametersRaw = %s", resp.Commands[0].parametersRaw)
	}
	if string(resp.Commands[1].parametersRaw) != `{"y":2}` {
		t.Fatalf("command 1 parametersRaw = %s", resp.Commands[1].parametersRaw)
	}
}
