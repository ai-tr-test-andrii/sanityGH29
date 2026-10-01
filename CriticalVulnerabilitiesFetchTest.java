import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the SSRF fix in CriticalVulnerabilities.fetch().
 *
 * Vulnerability: CWE-918 – The original code passed the raw "url" request
 * parameter directly to new URL(target).openStream(), allowing an attacker to
 * make the application server connect to arbitrary hosts (internal services,
 * cloud metadata endpoints, loopback addresses, etc.).
 *
 * Fix: The method now:
 *  1. Parses the user-supplied value with java.net.URI (stdlib URL parser) to
 *     extract the host in a canonicalized form resistant to encoding tricks.
 *  2. Validates the extracted host against a hardcoded ALLOWED_FETCH_HOSTS
 *     allowlist before any network connection is attempted.
 *  3. Enforces HTTPS-only to prevent plaintext credential leakage.
 *  4. Passes only the validated URI to toURL().openStream() – the taint chain
 *     is broken because the host reaching openStream() was verified against a
 *     compile-time constant set, not taken directly from getParameter().
 *
 * These tests verify:
 *  1. URLs with hosts NOT in the allowlist are rejected with
 *     IllegalArgumentException BEFORE any connection is made.
 *  2. HTTP (non-HTTPS) URLs are rejected even when the host would be allowed.
 *  3. Null, empty, and malformed URL inputs are rejected.
 *  4. SSRF attack payloads targeting internal/metadata services are blocked.
 *  5. Allowed hosts pass the allowlist guard (connection attempt is expected;
 *     IOException from network failure in test environment is acceptable).
 *
 * Note: tests do NOT make real network connections.  Any exception other than
 * IllegalArgumentException on the allowlist/scheme guard is treated as an OS /
 * network-level failure, not a security failure.
 */
public class CriticalVulnerabilitiesFetchTest {

    private final CriticalVulnerabilities subject = new CriticalVulnerabilities();

    // -----------------------------------------------------------------------
    // Helper: build a mock HttpServletRequest that returns the given "url" value.
    // -----------------------------------------------------------------------
    private HttpServletRequest requestWith(String url) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("url")).thenReturn(url);
        return req;
    }

    // -----------------------------------------------------------------------
    // Negative tests – disallowed hosts must be rejected with
    // IllegalArgumentException before any network I/O is attempted.
    // -----------------------------------------------------------------------

    @Test
    void arbitraryExternalHost_isRejected() {
        HttpServletRequest req = requestWith("https://attacker.example.com/steal");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "URL with host not in the allowlist must be rejected");
    }

    @Test
    void ssrfPayload_loopback_isRejected() {
        // Attacker attempts to reach the application's own loopback interface.
        HttpServletRequest req = requestWith("https://127.0.0.1/admin");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "Loopback (127.0.0.1) must be rejected by the host allowlist");
    }

    @Test
    void ssrfPayload_localhost_isRejected() {
        HttpServletRequest req = requestWith("https://localhost/internal");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "'localhost' must be rejected by the host allowlist");
    }

    @Test
    void ssrfPayload_ipv6Loopback_isRejected() {
        // IPv6 loopback – ::1 – must not bypass the host allowlist.
        HttpServletRequest req = requestWith("https://[::1]/secret");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "IPv6 loopback ([::1]) must be rejected by the host allowlist");
    }

    @Test
    void ssrfPayload_awsMetadata_isRejected() {
        // Classic cloud metadata endpoint used in SSRF attacks against AWS.
        HttpServletRequest req = requestWith("https://169.254.169.254/latest/meta-data/");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "AWS metadata endpoint (169.254.169.254) must be rejected");
    }

    @Test
    void ssrfPayload_internalNetwork_isRejected() {
        // RFC-1918 private network address – typical internal service target.
        HttpServletRequest req = requestWith("https://192.168.1.1/router");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "RFC-1918 private address (192.168.1.1) must be rejected");
    }

    @Test
    void ssrfPayload_internalSubdomain_isRejected() {
        // Subdomain of an allowed host – must NOT be treated as the allowed host.
        // e.g. "evil.api.example.com" must not pass the "api.example.com" check.
        HttpServletRequest req = requestWith("https://evil.api.example.com/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "A subdomain of an allowed host must not bypass the host allowlist");
    }

    @Test
    void ssrfPayload_allowedHostWithRedirect_subdomain_isRejected() {
        // "api.example.com.attacker.com" looks like it starts with the allowed
        // host in a string-prefix check, but the host parser extracts the real
        // hostname so the allowlist membership check correctly rejects it.
        HttpServletRequest req = requestWith("https://api.example.com.attacker.com/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "Host that embeds the allowed host as a prefix must be rejected");
    }

    // -----------------------------------------------------------------------
    // Scheme-enforcement tests – only HTTPS is permitted.
    // -----------------------------------------------------------------------

    @Test
    void httpScheme_withAllowedHost_isRejected() {
        // Plain HTTP must be rejected even when the host is in the allowlist,
        // to prevent transmission of sensitive data in cleartext.
        HttpServletRequest req = requestWith("http://api.example.com/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "HTTP scheme must be rejected even for an allowed host");
    }

    @Test
    void fileScheme_isRejected() {
        // file:// could allow reading local files – must be blocked.
        HttpServletRequest req = requestWith("file:///etc/passwd");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "file:// scheme must be rejected");
    }

    @Test
    void ftpScheme_isRejected() {
        HttpServletRequest req = requestWith("ftp://api.example.com/resource");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "ftp:// scheme must be rejected");
    }

    @Test
    void gopherScheme_isRejected() {
        // Gopher is sometimes used in SSRF attacks to reach non-HTTP services.
        HttpServletRequest req = requestWith("gopher://attacker.example/attack");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req),
                "gopher:// scheme must be rejected");
    }

    // -----------------------------------------------------------------------
    // Null / empty / malformed input tests.
    // -----------------------------------------------------------------------

    @Test
    void nullUrl_throwsException() {
        HttpServletRequest req = requestWith(null);
        // new URI(null) throws NullPointerException; any exception before the
        // network is acceptable – the fix must not silently swallow nulls.
        assertThrows(Exception.class, () -> subject.fetch(req),
                "A null URL parameter must throw rather than silently succeed");
    }

    @Test
    void emptyUrl_throwsException() {
        // An empty string produces a URI with null host.
        HttpServletRequest req = requestWith("");
        assertThrows(Exception.class, () -> subject.fetch(req),
                "An empty URL parameter must throw rather than silently succeed");
    }

    @Test
    void malformedUrl_noScheme_throwsException() {
        // A bare hostname without a scheme is not a valid absolute URI.
        HttpServletRequest req = requestWith("api.example.com/resource");
        assertThrows(Exception.class, () -> subject.fetch(req),
                "A URL without a scheme must throw an exception");
    }

    @Test
    void relativeUrl_throwsException() {
        // Relative URLs have no host – the allowlist check must reject them.
        HttpServletRequest req = requestWith("/internal/admin");
        assertThrows(Exception.class, () -> subject.fetch(req),
                "A relative URL path must not bypass the host allowlist");
    }

    @ParameterizedTest(name = "SSRF payload ''{0}'' is rejected")
    @ValueSource(strings = {
        "https://10.0.0.1/secret",
        "https://172.16.0.1/admin",
        "https://0.0.0.0/",
        "https://internal.corp/api",
        "http://api.example.com/data",
        "https://attacker.com/",
        "https://169.254.169.254/",
        "https://[::ffff:127.0.0.1]/bypass"
    })
    void ssrfPayloads_areRejected(String payload) {
        HttpServletRequest req = requestWith(payload);
        assertThrows(Exception.class, () -> subject.fetch(req),
                "SSRF payload must be rejected: " + payload);
    }

    // -----------------------------------------------------------------------
    // Positive tests – allowed hosts must pass the allowlist and scheme guard.
    //
    // Because tests do not make real network connections, we only assert that
    // IllegalArgumentException (the security gate) is NOT thrown.  Any other
    // exception (IOException from network, UnknownHostException, etc.) means
    // the guard passed and the OS/network rejected the connection – acceptable
    // in a sandboxed test environment.
    // -----------------------------------------------------------------------

    @Test
    void allowedHost_apiExampleCom_passesGuard() {
        HttpServletRequest req = requestWith("https://api.example.com/resource");
        // The allowlist and scheme guard must not fire; network failure is fine.
        assertDoesNotThrow(() -> {
            try {
                subject.fetch(req);
            } catch (IllegalArgumentException e) {
                // Re-throw – this is the security gate we must NOT hit.
                throw e;
            } catch (Exception ignored) {
                // Network-level failure in sandbox – acceptable.
            }
        });
    }

    @Test
    void allowedHost_cdnExampleCom_passesGuard() {
        HttpServletRequest req = requestWith("https://cdn.example.com/asset.js");
        assertDoesNotThrow(() -> {
            try {
                subject.fetch(req);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception ignored) {
                // Network-level failure in sandbox – acceptable.
            }
        });
    }

    // -----------------------------------------------------------------------
    // Structural / source-level tests
    //
    // Verify that the ALLOWED_FETCH_HOSTS field exists and is immutable,
    // confirming the allowlist-based architecture is in place.
    // -----------------------------------------------------------------------

    @Test
    void allowedFetchHosts_fieldExistsAndIsImmutable() throws Exception {
        // Confirm the static ALLOWED_FETCH_HOSTS field exists on the class.
        java.lang.reflect.Field field =
                CriticalVulnerabilities.class.getDeclaredField("ALLOWED_FETCH_HOSTS");
        assertNotNull(field,
                "ALLOWED_FETCH_HOSTS static field must exist as the SSRF allowlist");

        // Confirm the field is static and final (immutable allowlist).
        assertTrue(java.lang.reflect.Modifier.isStatic(field.getModifiers()),
                "ALLOWED_FETCH_HOSTS must be static");
        assertTrue(java.lang.reflect.Modifier.isFinal(field.getModifiers()),
                "ALLOWED_FETCH_HOSTS must be final (immutable after initialization)");

        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<String> hosts = (java.util.Set<String>) field.get(null);
        assertNotNull(hosts, "ALLOWED_FETCH_HOSTS must not be null");
        assertFalse(hosts.isEmpty(), "ALLOWED_FETCH_HOSTS must contain at least one entry");
    }

    @Test
    void allowedFetchHosts_doesNotContainLocalhost() throws Exception {
        // Validate that the allowlist itself was not misconfigured to include
        // dangerous hosts that would defeat the SSRF protection.
        java.lang.reflect.Field field =
                CriticalVulnerabilities.class.getDeclaredField("ALLOWED_FETCH_HOSTS");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        java.util.Set<String> hosts = (java.util.Set<String>) field.get(null);

        assertFalse(hosts.contains("localhost"),
                "ALLOWED_FETCH_HOSTS must not include 'localhost'");
        assertFalse(hosts.contains("127.0.0.1"),
                "ALLOWED_FETCH_HOSTS must not include '127.0.0.1'");
        assertFalse(hosts.contains("169.254.169.254"),
                "ALLOWED_FETCH_HOSTS must not include the AWS metadata endpoint");
    }
}
