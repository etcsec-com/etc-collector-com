// Package network provides network probe functions for Active Directory security testing.
//
// # Network Probes Overview
//
// This package implements **opt-in** network probes that actively test for security vulnerabilities
// by making network requests to domain resources. These probes are disabled by default and require
// explicit administrator consent due to:
//   - Potential generation of security alerts (SIEM, IDS/IPS, EDR)
//   - Network traffic generation to production systems
//   - Possible impact on monitored services
//
// # Why Opt-In?
//
// Unlike passive LDAP queries or SYSVOL file reads, network probes actively probe services:
//   - ESC8: Makes HTTP requests to potential Certificate Authority endpoints
//   - Zone Transfer: Attempts DNS AXFR queries to domain controllers
//
// These actions may trigger:
//   - Firewall/IDS alerts (unusual DNS AXFR attempts, HTTP to certsrv/)
//   - Security log entries (failed authentication, zone transfer denials)
//   - Network monitoring alerts (unexpected protocol usage)
//
// Users should enable probes only when:
//  1. Authorized to perform security testing on the domain
//  2. Coordinated with security operations team (to avoid false alarms)
//  3. Testing in controlled environment or during maintenance windows
//
// # Probes Implemented
//
// ## ESC8: HTTP Certificate Enrollment Detection
//
// **What it detects:**
//
//	ADCS ESC8 vulnerability (HTTP web enrollment exposed over unencrypted HTTP instead of HTTPS)
//
// **Attack scenario:**
//  1. Attacker intercepts HTTP traffic to Certificate Authority (no TLS protection)
//  2. Performs NTLM relay attack during certificate enrollment
//  3. Requests certificate for privileged user (Domain Admin)
//  4. Uses certificate for Kerberos PKINIT authentication as Domain Admin
//  5. Full domain compromise
//
// **How detection works:**
//   - Probes http://CA-hostname/certsrv/ (ADCS web enrollment endpoint)
//   - Checks HTTP status codes:
//   - 200 OK → Web enrollment active, accessible without auth (critical)
//   - 401 Unauthorized → Web enrollment active but requires auth (still vulnerable to relay)
//   - 404 Not Found → Web enrollment not exposed or HTTPS-only (secure)
//   - Connection refused → Service not running (secure)
//
// **Why it matters:**
//   - ESC8 is a critical ADCS vulnerability (CVE-2022-26923 related)
//   - Exploited via NTLM relay + certificate request = instant Domain Admin
//   - Common misconfiguration: admins enable HTTP for "convenience"
//
// **Remediation:**
//   - Disable HTTP web enrollment
//   - Enable HTTPS-only access with certificate authentication
//   - Configure Extended Protection for Authentication (EPA)
//
// ## DNS Zone Transfer (AXFR) Detection
//
// **What it detects:**
//
//	Unrestricted DNS zone transfers allowing domain reconnaissance
//
// **Attack scenario:**
//  1. Attacker queries DNS server with AXFR request
//  2. DNS server returns entire zone database (all hostnames, IPs, records)
//  3. Attacker gains complete network topology:
//     - All computer names and IPs
//     - Service locations (DC, CA, Exchange, file servers)
//     - User workstation names
//  4. Targeted attacks against discovered systems
//
// **How detection works:**
//   - Establishes TCP connection to DNS port 53 on domain controller
//   - Sends DNS AXFR query for domain zone
//   - Checks response:
//   - RCODE=0 (NOERROR) + records returned → zone transfer allowed (vulnerable)
//   - RCODE=5 (REFUSED) → zone transfer denied (secure)
//   - Connection timeout → DNS TCP disabled (unusual but secure)
//
// **Why it matters:**
//   - Zone transfers should be restricted to secondary DNS servers only
//   - Open zone transfers = complete network blueprint for attackers
//   - Industry-standard vulnerability since 1990s, still commonly found
//
// **Remediation:**
//   - Configure DNS zone transfer restrictions:
//   - DNS Manager → Zone Properties → Zone Transfers → "Only to the following servers"
//   - Limit to specific IP addresses of authorized secondary DNS servers
//   - Enable DNSSEC for zone integrity (optional but recommended)
//
// # DNS Protocol Details (AXFR)
//
// DNS operates on:
//   - UDP port 53 (queries/responses, 512 bytes max traditionally)
//   - TCP port 53 (zone transfers, large responses)
//
// AXFR (zone transfer) uses TCP exclusively because zone data exceeds UDP size limits.
//
// AXFR Query Structure (RFC 5936):
//   - Standard DNS query with QTYPE=252 (AXFR)
//   - TCP framing: 2-byte length prefix + DNS message
//
// AXFR Response:
//   - Series of DNS answers containing all zone records (SOA, A, AAAA, CNAME, MX, etc.)
//   - Starts with SOA record
//   - Ends with duplicate SOA record (zone transfer completion marker)
//   - May be split across multiple TCP messages
//
// # HTTP Status Codes (ESC8)
//
// Status codes from http://CA/certsrv/ probe:
//
//	Code | Meaning                     | ESC8 Vulnerable?
//	-----|-----------------------------|-----------------
//	200  | OK, no auth required        | YES (critical)
//	401  | Unauthorized, auth required | YES (relay possible)
//	404  | Not Found                   | NO (HTTPS-only or disabled)
//	403  | Forbidden                   | NO (IP restrictions)
//	500  | Server Error                | Unknown (may be misconfigured)
//	Timeout/Refused                   | NO (service not exposed)
//
// # Performance Considerations
//
// - ESC8 probe: ~5 seconds timeout per DC (HTTP client timeout)
// - Zone transfer probe: ~5 seconds timeout per zone (TCP connection + query)
// - Probes run sequentially (not parallelized to avoid overwhelming services)
// - Probe count: N_DCs (ESC8) + N_zones (AXFR)
// - Typical domain: 2-5 DCs, 1-3 zones = 3-8 probes × 5s = 15-40 seconds total
//
// # Security & Operational Impact
//
// **Log entries generated:**
//   - IIS logs on CA: GET /certsrv/ HTTP/1.1 (ESC8 probe)
//   - DNS server logs: AXFR query from etc-collector source IP
//   - Windows Security logs: Network connection attempts (if audited)
//
// **SIEM/IDS alerts (possible):**
//   - "DNS zone transfer attempt detected"
//   - "HTTP access to ADCS certsrv without authentication"
//   - "Unusual DNS query type (AXFR) from unexpected source"
//
// **Mitigation of false positives:**
//   - Whitelist etc-collector source IP in security monitoring
//   - Document authorized security scanning in change management
//   - Run probes during maintenance windows if alerts are concern
//
// # References
//
//   - ESC8: "Certified Pre-Owned" by Will Schroeder & Lee Christensen (SpecterOps)
//     https://posts.specterops.io/certified-pre-owned-d95910965cd2
//   - RFC 5936: DNS Zone Transfer Protocol (AXFR)
//     https://datatracker.ietf.org/doc/html/rfc5936
//   - RFC 1035: Domain Names - Implementation and Specification
//     https://datatracker.ietf.org/doc/html/rfc1035
//   - CVE-2022-26923: Active Directory Domain Services Elevation of Privilege (related to ADCS)
package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/etcsec-com/etc-collector/pkg/types"
)

const probeTimeout = 5 * time.Second

// RunNetworkProbes executes HTTP and DNS probes and returns results
func RunNetworkProbes(ctx context.Context, certTemplates []types.CertTemplate, dnsZones []types.DNSZone, domainControllers []string) (*types.NetworkProbeResults, []types.Warning) {
	results := &types.NetworkProbeResults{}
	var warnings []types.Warning

	// ESC8: HTTP probe for ADCS web enrollment
	esc8Results, esc8Warnings := probeESC8(ctx, domainControllers)
	results.ESC8Results = esc8Results
	warnings = append(warnings, esc8Warnings...)

	// DNS zone transfer probe
	ztResults, ztWarnings := probeZoneTransfer(ctx, dnsZones, domainControllers)
	results.ZoneTransfers = ztResults
	warnings = append(warnings, ztWarnings...)

	// Print Spooler probe (PrintNightmare / PrinterBug detection)
	spoolerResults, spoolerWarnings := probeSpooler(ctx, domainControllers)
	results.SpoolerResults = spoolerResults
	warnings = append(warnings, spoolerWarnings...)

	// LDAPS TLS version probe (weak TLS detection)
	tlsResults, tlsWarnings := probeLDAPSTLS(ctx, domainControllers)
	results.TLSResults = tlsResults
	warnings = append(warnings, tlsWarnings...)

	return results, warnings
}

// probeESC8 checks for ADCS ESC8 vulnerability by probing HTTP web enrollment endpoints.
//
// Methodology:
//  1. For each domain controller (potential CA host):
//     a. Construct URL: http://hostname/certsrv/
//     b. Send HTTP GET request with 5-second timeout
//     c. Analyze HTTP status code (don't follow redirects)
//  2. Interpret results:
//     - 200 or 401: Web enrollment is active (vulnerable)
//     - 404, 403, or error: Web enrollment not exposed via HTTP (secure)
//
// Status Code Meanings:
//   - 200 OK: Enrollment page accessible without authentication (CRITICAL - immediate access)
//   - 401 Unauthorized: Enrollment requires authentication but HTTP exposed (HIGH - relay vulnerable)
//   - 404 Not Found: certsrv not available on HTTP (secure)
//   - Connection error: Service not running or blocked (secure)
//
// False Positives:
//   - Non-CA domain controllers return 404 (expected, not a security issue)
//   - Only DCs running ADCS Certificate Authority role will respond with 200/401
//
// Returns:
//   - ESC8ProbeResult per DC with status code and vulnerability flag
//   - Warning if no DCs provided (can't perform probe)
func probeESC8(ctx context.Context, domainControllers []string) ([]types.ESC8ProbeResult, []types.Warning) {
	var results []types.ESC8ProbeResult
	var warnings []types.Warning

	// Try each DC as potential CA host
	client := &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, dc := range domainControllers {
		result := types.ESC8ProbeResult{
			CAHostname: dc,
			CAName:     dc,
		}

		url := fmt.Sprintf("http://%s/certsrv/", dc)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		resp.Body.Close()

		result.StatusCode = resp.StatusCode
		// 200 or 401 means web enrollment is active
		if resp.StatusCode == 200 || resp.StatusCode == 401 {
			result.WebEnrollment = true
		}
		results = append(results, result)
	}

	if len(domainControllers) == 0 {
		warnings = append(warnings, types.Warning{
			Code:              "PROBE_NO_TARGETS",
			Message:           "No domain controllers found for ESC8 HTTP probe",
			AffectedDetectors: []string{"ESC8_HTTP_ENROLLMENT"},
		})
	}

	return results, warnings
}

// probeZoneTransfer attempts DNS AXFR (zone transfer) queries to detect unrestricted zone transfers.
//
// Methodology:
//  1. Select first domain controller as DNS server (DC port 53)
//  2. For each DNS zone in the domain:
//     a. Open TCP connection to DNS port 53
//     b. Send AXFR query: DNS header + question section (QTYPE=252, QCLASS=1)
//     c. Read response and parse DNS header
//     d. Check RCODE and ANCOUNT fields
//  3. Interpret results:
//     - RCODE=0 (NOERROR) + ANCOUNT>0: Zone transfer allowed (vulnerable)
//     - RCODE=5 (REFUSED): Zone transfer denied (secure)
//     - Other RCODE or timeout: Misconfiguration or error
//
// DNS AXFR Protocol (RFC 5936):
//   - Uses TCP (not UDP) due to large response size
//   - Client sends AXFR query (QTYPE=252)
//   - Server responds with:
//   - SOA record (zone start)
//   - All zone records (A, AAAA, CNAME, MX, TXT, etc.)
//   - SOA record again (zone end marker)
//
// Response Parsing:
//   - Read 2-byte length prefix (TCP DNS framing)
//   - Read DNS header (12 bytes):
//   - Bytes 0-1: Transaction ID
//   - Bytes 2-3: Flags (includes RCODE in bits 0-3 of byte 3)
//   - Bytes 4-5: QDCOUNT (question count)
//   - Bytes 6-7: ANCOUNT (answer count)
//   - Bytes 8-9: NSCOUNT (authority count)
//   - Bytes 10-11: ARCOUNT (additional count)
//   - RCODE extraction: response[3] & 0x0F
//   - 0 = NOERROR (success)
//   - 5 = REFUSED (denied)
//   - 2 = SERVFAIL (server error)
//
// Security Note:
//   - Only tests first DC (assumes consistent DNS config across DCs)
//   - Real zone transfer would receive hundreds/thousands of records
//   - Probe only checks if transfer is permitted, doesn't download full zone
//
// False Positives:
//   - None (AXFR allowed = definite vulnerability)
//   - Connection timeouts may indicate firewall blocking (secure but should investigate)
//
// Returns:
//   - ZoneTransferResult per zone with allowed flag and error details
//   - No warnings (missing DCs/zones handled gracefully)
func probeZoneTransfer(ctx context.Context, dnsZones []types.DNSZone, domainControllers []string) ([]types.ZoneTransferResult, []types.Warning) {
	var results []types.ZoneTransferResult
	var warnings []types.Warning

	if len(domainControllers) == 0 || len(dnsZones) == 0 {
		return results, warnings
	}

	// Use first DC as DNS server
	dnsServer := domainControllers[0] + ":53"

	for _, zone := range dnsZones {
		result := types.ZoneTransferResult{
			Zone: zone.Name,
		}

		// Try TCP connection to port 53 with AXFR-like query
		conn, err := net.DialTimeout("tcp", dnsServer, probeTimeout)
		if err != nil {
			result.Error = fmt.Sprintf("DNS TCP connection failed: %v", err)
			results = append(results, result)
			continue
		}

		// Build minimal AXFR query
		query := buildAXFRQuery(zone.Name)
		conn.SetDeadline(time.Now().Add(probeTimeout))

		// Send length-prefixed TCP DNS message
		length := uint16(len(query))
		tcpMsg := append([]byte{byte(length >> 8), byte(length)}, query...)
		_, err = conn.Write(tcpMsg)
		if err != nil {
			conn.Close()
			result.Error = fmt.Sprintf("DNS query send failed: %v", err)
			results = append(results, result)
			continue
		}

		// Read response header
		respBuf := make([]byte, 2)
		_, err = conn.Read(respBuf)
		if err != nil {
			conn.Close()
			result.Error = fmt.Sprintf("DNS response read failed: %v", err)
			results = append(results, result)
			continue
		}

		respLen := int(respBuf[0])<<8 | int(respBuf[1])
		if respLen > 0 {
			respData := make([]byte, respLen)
			n, _ := conn.Read(respData)
			if n >= 12 {
				// Check RCODE in response header (bits 12-15 of flags)
				rcode := respData[3] & 0x0F
				ancount := int(respData[6])<<8 | int(respData[7])
				if rcode == 0 && ancount > 0 {
					result.Allowed = true
					result.RecordCount = ancount
				}
			}
		}

		conn.Close()
		results = append(results, result)
	}

	return results, warnings
}

// buildAXFRQuery constructs a DNS query message for AXFR (zone transfer) request.
//
// DNS Message Structure (RFC 1035 Section 4.1):
//
//	Section        | Size      | Description
//	---------------|-----------|----------------------------------------------
//	Header         | 12 bytes  | Transaction ID, flags, section counts
//	Question       | Variable  | Zone name + QTYPE + QCLASS
//	Answer         | 0 bytes   | (empty in query)
//	Authority      | 0 bytes   | (empty in query)
//	Additional     | 0 bytes   | (empty in query)
//
// Header Fields (12 bytes):
//
//	Offset | Size | Field    | Value    | Description
//	-------|------|----------|----------|--------------------------------
//	0      | 2    | ID       | 0x1234   | Transaction ID (arbitrary)
//	2      | 2    | Flags    | 0x0000   | QR=0 (query), OPCODE=0 (standard), RD=0
//	4      | 2    | QDCOUNT  | 0x0001   | 1 question
//	6      | 2    | ANCOUNT  | 0x0000   | 0 answers (query)
//	8      | 2    | NSCOUNT  | 0x0000   | 0 authority records
//	10     | 2    | ARCOUNT  | 0x0000   | 0 additional records
//
// Question Section (variable length):
//
//	Field   | Size      | Value             | Description
//	--------|-----------|-------------------|----------------------------------
//	QNAME   | Variable  | Encoded zone name | DNS name encoding (length-prefixed labels)
//	QTYPE   | 2 bytes   | 0x00FC (252)      | AXFR query type
//	QCLASS  | 2 bytes   | 0x0001 (1)        | IN (Internet) class
//
// QTYPE Values:
//   - 252 (0x00FC): AXFR (zone transfer request)
//   - 1 (0x0001): A (host address query)
//   - 15 (0x000F): MX (mail exchange query)
//   - 28 (0x001C): AAAA (IPv6 address query)
//
// Example: AXFR query for "example.com"
//
//	Header: [0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
//	QNAME:  [0x07, 'e','x','a','m','p','l','e', 0x03, 'c','o','m', 0x00]
//	QTYPE:  [0x00, 0xFC]
//	QCLASS: [0x00, 0x01]
//
// Returns complete DNS query ready for TCP transmission (with 2-byte length prefix added by caller).
func buildAXFRQuery(zone string) []byte {
	// DNS header: ID=0x1234, QR=0, OPCODE=0, RD=1
	header := []byte{
		0x12, 0x34, // ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}

	// Question section: encode zone name
	question := encodeDNSName(zone)
	question = append(question, 0x00, 0xFC) // QTYPE: AXFR (252)
	question = append(question, 0x00, 0x01) // QCLASS: IN

	return append(header, question...)
}

// probeSpooler checks if Print Spooler service is accessible on domain controllers.
// A running spooler is required for PrintNightmare (CVE-2021-34527) and PrinterBug exploitation.
// Detection: TCP connect to port 445 (SMB) — if port open, spooler is likely running.
// A more precise check would open \pipe\spoolss but requires SMB protocol implementation.
func probeSpooler(ctx context.Context, domainControllers []string) ([]types.SpoolerProbeResult, []types.Warning) {
	var results []types.SpoolerProbeResult
	var warnings []types.Warning

	for _, dc := range domainControllers {
		result := types.SpoolerProbeResult{
			DCHostname: dc,
		}

		// TCP connect to port 445 (SMB)
		conn, err := net.DialTimeout("tcp", dc+":445", probeTimeout)
		if err != nil {
			result.Error = fmt.Sprintf("SMB port not accessible: %v", err)
			results = append(results, result)
			continue
		}
		conn.Close()

		// Port 445 is open — spooler is likely running on a DC
		// (DCs typically have spooler enabled by default)
		result.SpoolerRunning = true
		results = append(results, result)
	}

	return results, warnings
}

// probeLDAPSTLS checks if LDAP/LDAPS accepts weak TLS versions (1.0 or 1.1).
// Tests both LDAPS (port 636) and STARTTLS on LDAP (port 389).
// Weak TLS allows downgrade attacks and exploitation of known protocol vulnerabilities.
func probeLDAPSTLS(ctx context.Context, domainControllers []string) ([]types.TLSProbeResult, []types.Warning) {
	var results []types.TLSProbeResult
	var warnings []types.Warning

	for _, dc := range domainControllers {
		result := types.TLSProbeResult{
			DCHostname: dc,
			Port:       636,
		}

		// Try 1: LDAPS on port 636 with TLS 1.0/1.1 handshake
		// Must set MinVersion=TLS10 explicitly since Go 1.22+ defaults to TLS 1.2
		dialer := &net.Dialer{Timeout: probeTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", dc+":636", &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS11,
		})
		if err == nil {
			conn.Close()
			result.WeakTLS = true
			results = append(results, result)
			continue
		}

		// Try 2: STARTTLS on port 389 (many DCs don't expose port 636)
		result.Port = 389
		tcpConn, err := net.DialTimeout("tcp", dc+":389", probeTimeout)
		if err != nil {
			result.Error = fmt.Sprintf("LDAP ports 636 and 389 unreachable: %v", err)
			results = append(results, result)
			continue
		}

		// Perform LDAP STARTTLS (Extended Operation OID 1.3.6.1.4.1.1466.20037)
		// Send a minimal LDAP ExtendedRequest for StartTLS
		startTLSReq := buildStartTLSRequest()
		_ = tcpConn.SetDeadline(time.Now().Add(probeTimeout))
		_, err = tcpConn.Write(startTLSReq)
		if err != nil {
			tcpConn.Close()
			result.Error = fmt.Sprintf("STARTTLS write failed: %v", err)
			results = append(results, result)
			continue
		}

		// Read LDAP ExtendedResponse
		respBuf := make([]byte, 1024)
		n, err := tcpConn.Read(respBuf)
		if err != nil || n < 10 {
			tcpConn.Close()
			result.Error = "STARTTLS response unreadable"
			results = append(results, result)
			continue
		}

		// Check if result code is success (0) — very simplified BER parse
		// The resultCode is typically at a fixed offset in the ExtendedResponse
		if !isLDAPSuccess(respBuf[:n]) {
			tcpConn.Close()
			result.Error = "STARTTLS rejected by server"
			results = append(results, result)
			continue
		}

		// STARTTLS accepted — now try TLS 1.0/1.1 handshake on the connection
		tlsConn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS11,
		})
		err = tlsConn.Handshake()
		tlsConn.Close()

		if err != nil {
			result.Error = fmt.Sprintf("STARTTLS TLS <=1.1 rejected (good): %v", err)
			results = append(results, result)
			continue
		}

		// TLS 1.0 or 1.1 was accepted via STARTTLS — weak configuration
		result.WeakTLS = true
		results = append(results, result)
	}

	return results, warnings
}

// buildStartTLSRequest builds a minimal LDAP ExtendedRequest for StartTLS
// OID: 1.3.6.1.4.1.1466.20037
func buildStartTLSRequest() []byte {
	// BER-encoded LDAP ExtendedRequest:
	// SEQUENCE { messageID INTEGER(1), ExtendedRequest [APPLICATION 23] { requestName [0] OID } }
	oid := "1.3.6.1.4.1.1466.20037"
	oidBytes := []byte(oid)

	// requestName [0] (context-specific, primitive, tag 0)
	requestName := append([]byte{0x80, byte(len(oidBytes))}, oidBytes...)

	// ExtendedRequest [APPLICATION 23] (constructed)
	extReq := append([]byte{0x77, byte(len(requestName))}, requestName...)

	// messageID INTEGER(1)
	msgID := []byte{0x02, 0x01, 0x01}

	// SEQUENCE
	inner := append(msgID, extReq...)
	return append([]byte{0x30, byte(len(inner))}, inner...)
}

// isLDAPSuccess checks if an LDAP response contains resultCode 0 (success)
func isLDAPSuccess(data []byte) bool {
	// Simplified: look for the ExtendedResponse result code
	// LDAP ExtendedResponse: SEQUENCE { messageID, ExtendedResponse [APPLICATION 24] { resultCode ENUM, ... } }
	// We scan for ENUMERATED tag (0x0a) followed by length 1 and value 0
	for i := 0; i < len(data)-2; i++ {
		if data[i] == 0x0a && data[i+1] == 0x01 {
			return data[i+2] == 0x00
		}
	}
	return false
}

// encodeDNSName encodes a domain name into DNS wire format (RFC 1035 Section 3.1).
//
// DNS Name Encoding:
//   - Domain names are encoded as length-prefixed labels
//   - Each label: 1-byte length + label bytes (max 63 chars per label)
//   - Labels separated by dots in original format
//   - Terminated by zero-length label (root)
//
// Example Encodings:
//
//	"example.com" →
//	  [0x07, 'e','x','a','m','p','l','e',  ← length 7 + "example"
//	   0x03, 'c','o','m',                   ← length 3 + "com"
//	   0x00]                                 ← root label (terminator)
//
//	"mail.example.com" →
//	  [0x04, 'm','a','i','l',               ← length 4 + "mail"
//	   0x07, 'e','x','a','m','p','l','e',   ← length 7 + "example"
//	   0x03, 'c','o','m',                   ← length 3 + "com"
//	   0x00]                                 ← root label
//
//	"." (root) → [0x00]                      ← just the root label
//
// Constraints:
//   - Maximum label length: 63 bytes
//   - Maximum total name length: 255 bytes
//   - Case-insensitive (typically lowercase in wire format)
//   - Labels use only: A-Z, a-z, 0-9, hyphen (no underscore except for SRV records)
//
// Compression (NOT used in this implementation):
//   - DNS protocol supports pointer compression for repeated names
//   - Format: 0xC0 + offset (saves bandwidth in responses)
//   - Not needed for AXFR queries (only one name)
//
// Returns encoded name with root label terminator.
func encodeDNSName(name string) []byte {
	var result []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			if len(label) > 0 {
				result = append(result, byte(len(label)))
				result = append(result, []byte(label)...)
			}
			start = i + 1
		}
	}
	result = append(result, 0x00) // Root label
	return result
}
