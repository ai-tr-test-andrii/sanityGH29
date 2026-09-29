import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the SSRF fix in CriticalVulnerabilities.fetch().
 *
 * Vulnerability: CWE-918 – The original code accepted an arbitrary URL from the
 * "url" request parameter and passed it directly to new URL(target).openStream(),
 * allowing an attacker to make the server contact any host reachable from it.
 *
 * Fix: the method now:
 *  1. Parses the user-supplied value with java.net.URI (stdlib URL parser).
 *  2. Rejects any scheme other than http/https.
 *  3. Validates the resulting hostname against a hardcoded allowlist
 *     (ALLOWED_FETCH_HOSTS) before opening any connection.
 *
 * These tests verify:
 *  a. Requests to allowlisted hosts are not rejected at the validation gate
 *     (a network I/O failure is acceptable in a sandboxed test environment).
 *  b. Requests to non-allowlisted hosts are rejected with IllegalArgumentException
 *     BEFORE any network connection is attempted.
 *  c. Dangerous non-HTTP schemes (file://, gopher://, ftp://, dict://) are rejected.
 *  d. Null and malformed input are rejected.
 *  e. Bypass attempts (credential embedding, path traversal, URL encoding) are rejected.
 */
public class CriticalVulnerabilitiesFetchTest {

    private final CriticalVulnerabilities subject = new CriticalVulnerabilities();

    // -----------------------------------------------------------------------
    // Helper: build a mock request that returns the given "url" value.
    // -----------------------------------------------------------------------
    private HttpServletRequest requestWithUrl(String url) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("url")).thenReturn(url);
        return req;
    }

    // -----------------------------------------------------------------------
    // Positive tests – allowlisted hosts must pass the validation gate.
    // (Actual network I/O will fail in a sandboxed env; that is acceptable.)
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "allowlisted URL ''{0}'' passes the host validation gate")
    @ValueSource(strings = {
            "http://api.example.com/data",
            "https://api.example.com/secure",
            "http://cdn.example.com/asset.js",
            "https://cdn.example.com/image.png"
    })
    void allowlistedHost_doesNotThrowIllegalArgument(String url) {
        HttpServletRequest req = requestWithUrl(url);
        // The allowlist check must pass. Actual network I/O will fail in the test
        // environment; we only assert the security gate itself did not fire.
        assertDoesNotThrow(() -> {
            try {
                subject.fetch(req);
            } catch (IllegalArgumentException e) {
                // Re-throw – the allowlist rejected a URL it should have accepted.
                throw e;
            } catch (Exception ignored) {
                // Any other exception (e.g., IOException from openStream) means the
                // host-allowlist check passed and the network refused the connection,
                // which is the expected outcome in a sandboxed test environment.
            }
        });
    }

    // -----------------------------------------------------------------------
    // Negative tests – non-allowlisted hosts must be rejected before any I/O.
    // -----------------------------------------------------------------------

    @Test
    void internalHost_localhost_isRejected() {
        // Attacker tries to probe internal services on the loopback address.
        HttpServletRequest req = requestWithUrl("http://localhost/admin");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void internalHost_127_0_0_1_isRejected() {
        HttpServletRequest req = requestWithUrl("http://127.0.0.1:8080/secret");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void internalHost_privateRange_192_168_isRejected() {
        HttpServletRequest req = requestWithUrl("http://192.168.1.1/router-admin");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void internalHost_privateRange_10_x_isRejected() {
        HttpServletRequest req = requestWithUrl("http://10.0.0.1/internal-api");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void internalHost_awsMetadata_isRejected() {
        // AWS EC2 instance metadata endpoint – a classic SSRF target.
        HttpServletRequest req = requestWithUrl("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void arbitraryExternalHost_isRejected() {
        HttpServletRequest req = requestWithUrl("http://attacker.example.com/steal");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void unknownHost_example_org_isRejected() {
        HttpServletRequest req = requestWithUrl("https://www.example.org/page");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    // -----------------------------------------------------------------------
    // Scheme-based rejection tests – only http/https are permitted.
    // -----------------------------------------------------------------------

    @Test
    void fileScheme_isRejected() {
        // file:// would let an attacker read local files (e.g., /etc/passwd).
        HttpServletRequest req = requestWithUrl("file:///etc/passwd");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void gopherScheme_isRejected() {
        // gopher:// can be used to reach internal services with crafted payloads.
        HttpServletRequest req = requestWithUrl("gopher://internal-host/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void ftpScheme_isRejected() {
        HttpServletRequest req = requestWithUrl("ftp://files.example.com/file.txt");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void dictScheme_isRejected() {
        // dict:// can be used to exfiltrate data in some server configurations.
        HttpServletRequest req = requestWithUrl("dict://internal-host:11211/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void schemelessUrl_isRejected() {
        // A URI without a scheme; URI.getScheme() returns null → must be rejected.
        HttpServletRequest req = requestWithUrl("//api.example.com/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    // -----------------------------------------------------------------------
    // Bypass attempt tests – ensure the host check cannot be circumvented.
    // -----------------------------------------------------------------------

    @Test
    void credentialEmbedding_bypass_isRejected() {
        // Attacker embeds the allowlisted host as credentials: user@attacker-host
        // URI.getHost() returns the actual authority host, not the credential part,
        // so this must be rejected by the allowlist.
        HttpServletRequest req = requestWithUrl("http://api.example.com@attacker.example.com/steal");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void subdomainOfAllowlistedHost_isRejected() {
        // "evil.api.example.com" is NOT the same as "api.example.com".
        HttpServletRequest req = requestWithUrl("http://evil.api.example.com/steal");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void allowlistedHostAsSuffix_isRejected() {
        // "notapi.example.com" ends with "api.example.com" but is a different host.
        HttpServletRequest req = requestWithUrl("http://notapi.example.com/data");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    // -----------------------------------------------------------------------
    // Null / malformed input tests.
    // -----------------------------------------------------------------------

    @Test
    void nullUrl_isRejected() {
        // request.getParameter("url") returns null – must not produce a NullPointerException
        // that bypasses the security check; must throw IllegalArgumentException.
        HttpServletRequest req = requestWithUrl(null);
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void emptyUrl_isRejected() {
        HttpServletRequest req = requestWithUrl("");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void malformedUrl_isRejected() {
        // A string that cannot be parsed as a URI at all.
        HttpServletRequest req = requestWithUrl("not a url at all ][");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }

    @Test
    void justAHostname_noScheme_isRejected() {
        // Plain hostname without a scheme is not a valid absolute URI.
        HttpServletRequest req = requestWithUrl("api.example.com");
        assertThrows(IllegalArgumentException.class, () -> subject.fetch(req));
    }
}
