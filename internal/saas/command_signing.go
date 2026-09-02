package saas

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// K3 (T_045) — Ed25519 verification of cloud-issued commands before executeCommand's
// switch dispatches on them. Wire format locked by TL Cloud against the design in
// docs/security-validation/coordination/k3-command-signing-cloud-request.md:
//
//	SIGN_INPUT =
//	  "etcsec-cmd-v1"  LF      domain-separation prefix, versioned
//	  collectorId      LF      lowercase canonical UUID
//	  commandId        LF      lowercase canonical UUID
//	  type             LF      exact token, e.g. UPDATE_CONFIG_AD
//	  expiresAt        LF      the EXACT string transmitted (we sign what we send)
//	  base64std(parametersRawBytes)    the EXACT JSON bytes of the parameters field
//
// Not "canonical JSON": json.Marshal doesn't sort keys the same way in Go as in Node,
// so a canonical-JSON signature would drift by construction. This byte string sidesteps
// canonicalization entirely — that's the whole point of parametersRaw being
// json.RawMessage instead of a re-marshaled map.
//
// Phase 2 (this ticket): verify what we can, reject nothing by default. Enforcement is
// phase 4, a later decision made once fleet coverage is measurable via
// CommandSigningStatus.UnsignedAccepted — not implemented here.
const signInputDomainPrefix = "etcsec-cmd-v1"

const (
	// commandSigningStateUnverified — no signing keys installed at all. The collector
	// cannot verify anything; every command, signed or not, runs unchecked. This is the
	// ONLY case that falls back to pre-signing behavior.
	commandSigningStateUnverified = "unverified"
	// commandSigningStateVerifying — at least one key installed. Signed commands are
	// verified and an invalid one is rejected; an unsigned command is still accepted
	// (phase 2 does not enforce) but counted.
	commandSigningStateVerifying = "verifying"
)

// rejectLF refuses a scalar containing a line feed (0x0A) before it can be written into
// SIGN_INPUT. Nothing enforces LF-freedom on a UUID, an enum token, or an RFC3339
// timestamp upstream — an embedded newline in any of them would shift what an attacker
// controls across a field boundary the signer never intended. Imposed here, not assumed.
func rejectLF(field, value string) error {
	if strings.ContainsRune(value, '\n') {
		return fmt.Errorf("%s contains a line feed (0x0A) — refusing to build SIGN_INPUT", field)
	}
	return nil
}

// buildSignInput constructs SIGN_INPUT exactly as locked by TL Cloud. parametersRaw
// MUST be the exact bytes received on the wire for the "parameters" field (Command's
// unexported parametersRaw, captured by UnmarshalJSON) — never a Go re-marshal of a
// decoded value.
func buildSignInput(collectorID, commandID, cmdType, expiresAt string, parametersRaw []byte) ([]byte, error) {
	for _, f := range []struct{ name, value string }{
		{"collectorId", collectorID},
		{"commandId", commandID},
		{"type", cmdType},
		{"expiresAt", expiresAt},
	} {
		if err := rejectLF(f.name, f.value); err != nil {
			return nil, err
		}
	}

	var buf bytes.Buffer
	buf.WriteString(signInputDomainPrefix)
	buf.WriteByte('\n')
	buf.WriteString(collectorID)
	buf.WriteByte('\n')
	buf.WriteString(commandID)
	buf.WriteByte('\n')
	buf.WriteString(cmdType)
	buf.WriteByte('\n')
	buf.WriteString(expiresAt)
	buf.WriteByte('\n')
	buf.WriteString(base64.StdEncoding.EncodeToString(parametersRaw))
	return buf.Bytes(), nil
}

// resolveSigningKey finds the key matching kid, valid at now. An unresolvable kid — no
// match, or a match outside its notBefore/notAfter window — is always an error, never a
// signal to fall back to unverified. That fallback is reserved for checkCommandSignature's
// "keys is totally empty" case; otherwise an attacker could send kid:"whatever" and
// downgrade every command to the unchecked path (K3, T_045 acceptance criterion).
func resolveSigningKey(keys []CommandSigningKey, kid string, now time.Time) (*CommandSigningKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("signature has no kid")
	}
	for i := range keys {
		k := &keys[i]
		if k.Kid != kid {
			continue
		}
		if k.NotBefore != "" {
			nb, err := time.Parse(time.RFC3339, k.NotBefore)
			if err != nil {
				return nil, fmt.Errorf("key %q has unparseable notBefore %q: %w", kid, k.NotBefore, err)
			}
			if now.Before(nb) {
				return nil, fmt.Errorf("key %q not yet valid (notBefore %s)", kid, k.NotBefore)
			}
		}
		if k.NotAfter != "" {
			na, err := time.Parse(time.RFC3339, k.NotAfter)
			if err != nil {
				return nil, fmt.Errorf("key %q has unparseable notAfter %q: %w", kid, k.NotAfter, err)
			}
			if now.After(na) {
				return nil, fmt.Errorf("key %q expired (notAfter %s)", kid, k.NotAfter)
			}
		}
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

// checkCommandSignature verifies cmd's Ed25519 signature before executeCommand's
// switch. Returns nil when the command is safe to dispatch — either because it
// genuinely verified, or because phase 2 explicitly allows it through unchecked.
//
//   - No keys installed at all → nothing can be verified; every command (signed or
//     not) is accepted, logged distinctly as unverified. The only unconditional
//     fallback.
//   - At least one key installed, command unsigned → still accepted (phase 2 doesn't
//     enforce), but logged distinctly and counted via unsignedCommandsAccepted — the
//     number TL Cloud's dashboard needs to watch the fleet migrate.
//   - At least one key installed, command signed → MUST verify: unknown kid, a key
//     outside its validity window, a foreign collectorId, or an altered payload are
//     all rejections. An attacker cannot downgrade to the unverified path by sending
//     an unresolvable kid.
func (d *Daemon) checkCommandSignature(cmd Command) error {
	d.mu.Lock()
	keys := append([]CommandSigningKey(nil), d.creds.CommandSigningPublicKeys...)
	collectorID := d.creds.CollectorID
	d.mu.Unlock()

	if len(keys) == 0 {
		d.recordUnverifiedCommand(cmd)
		return nil
	}

	if cmd.Signature == nil {
		d.recordUnsignedAccepted(cmd)
		return nil
	}

	if cmd.CollectorID != collectorID {
		return fmt.Errorf("envelope collectorId %q does not match this collector", cmd.CollectorID)
	}

	key, err := resolveSigningKey(keys, cmd.Signature.Kid, time.Now().UTC())
	if err != nil {
		return err
	}

	signInput, err := buildSignInput(cmd.CollectorID, cmd.CommandID, cmd.Type, cmd.ExpiresAt, cmd.parametersRaw)
	if err != nil {
		return fmt.Errorf("build sign input: %w", err)
	}

	pubKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("malformed public key for kid %q", key.Kid)
	}
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed signature (kid %q)", key.Kid)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKey), signInput, sig) {
		return fmt.Errorf("signature verification failed (kid %q)", key.Kid)
	}

	d.mu.Lock()
	d.lastVerifiedKid = key.Kid
	d.mu.Unlock()
	return nil
}

// recordUnverifiedCommand logs, distinctly from a rejection, that this command ran
// with zero signature verification because no key set is installed at all — the only
// case phase 2 allows through unchecked (T_045 acceptance: "absence totale de clé =
// chemin non vérifié documenté ET journalisé, jamais silencieux").
func (d *Daemon) recordUnverifiedCommand(cmd Command) {
	d.logger.Info("Command signature: unverified (no signing keys installed)",
		"commandId", cmd.CommandID, "type", cmd.Type)
}

// recordUnsignedAccepted logs and counts a command that arrived without a signature
// while at least one signing key IS installed. Phase 2 still accepts it — no default
// rejection — but this counter is what lets TL Cloud's dashboard watch the fleet
// migrate off the unsigned path before enforcement is ever proposed.
func (d *Daemon) recordUnsignedAccepted(cmd Command) {
	d.mu.Lock()
	d.unsignedCommandsAccepted++
	n := d.unsignedCommandsAccepted
	d.mu.Unlock()
	d.logger.Warn("Command signature: unsigned command accepted (keys installed — phase 2 does not enforce)",
		"commandId", cmd.CommandID, "type", cmd.Type, "unsignedAcceptedTotal", n)
}

// commandSigningStatus snapshots command-signing state for the outgoing health report.
func (d *Daemon) commandSigningStatus() *CommandSigningStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := commandSigningStateUnverified
	if len(d.creds.CommandSigningPublicKeys) > 0 {
		state = commandSigningStateVerifying
	}
	return &CommandSigningStatus{
		State:            state,
		Kid:              d.lastVerifiedKid,
		UnsignedAccepted: d.unsignedCommandsAccepted,
	}
}

// equalSigningKeys reports whether two key sets are identical, field for field and in
// order. Used to avoid a needless disk write + log line every time a response happens
// to re-include the same currently-valid set.
func equalSigningKeys(a, b []CommandSigningKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mergeCommandSigningKeys stores a freshly-published key set (K3, T_045).
//
// B_141 (T_081) — the collector-side trust anchor: a key set is accepted
// automatically only the FIRST time (bootstrap, when nothing is pinned yet —
// no more trust than enrollment already places in this channel). Once a set
// is pinned, a DIFFERENT one arriving later is refused, not silently
// substituted. Established before fixing, not assumed: PollCommands' and the
// health-check response's CommandSigningPublicKeys field — the only two
// callers of this function — travel over the exact same channel
// checkCommandSignature's verification exists to add some protection
// against tampering with. Without this pin, an attacker able to publish
// through that channel (e.g. a compromised backend, not just a network MITM
// — TLS already covers that case) could mint their own Ed25519 keypair,
// publish the public half as "the trusted key" via this same function, and
// sign their own malicious commands with it — checkCommandSignature would
// verify them as genuine. Pinning closes that: publishing a new "trusted"
// key through this channel no longer has any effect once one is already
// pinned.
//
// This does not fully solve K3: a genuine planned rotation (the cloud
// legitimately retiring one signing key for another) has no automatic path
// here — that needs a cloud-side counterpart this ticket doesn't have (e.g.
// the new key co-signed by the outgoing one, so a rotation can be verified
// without trusting the channel itself). Until that exists, an intentional
// rotation requires local operator action (clearing
// CommandSigningPublicKeys from credentials.json, or a fresh enrollment) —
// documented here rather than silently degraded.
func (d *Daemon) mergeCommandSigningKeys(keys []CommandSigningKey) {
	if len(keys) == 0 {
		return
	}

	d.mu.Lock()
	current := d.creds.CommandSigningPublicKeys
	if len(current) > 0 {
		alreadyPinned := equalSigningKeys(current, keys)
		d.mu.Unlock()
		if !alreadyPinned {
			d.logger.Warn("Command signing key set changed upstream but was NOT applied — "+
				"a pinned key set only changes via explicit local operator action, never "+
				"automatically from a poll/health response (B_141, T_081)",
				"pinnedKeyCount", len(current), "proposedKeyCount", len(keys))
		}
		return
	}
	d.creds.CommandSigningPublicKeys = keys
	d.mu.Unlock()

	if err := d.credStore.Save(d.creds); err != nil {
		d.logger.Warn("Failed to persist command signing keys", "error", err)
		return
	}
	d.logger.Info("Command signing keys pinned (first receipt)", "count", len(keys))
}
