import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SSRF remediation in InfrastructureVulns.fetchUrl().
 *
 * The fix uses java.net.URI to parse the user-supplied URL and then validates
 * the host against a static allowlist (ALLOWED_HOSTS) and restricts the scheme
 * to http/https before allowing the connection.
 *
 * These tests verify:
 *   1. Requests to allowed hosts succeed (positive path).
 *   2. Requests to disallowed / internal hosts are blocked (SSRF prevention).
 *   3. Non-http/https schemes (file://, ftp://, etc.) are blocked.
 *   4. Edge-case bypass attempts (null host, userinfo-based bypasses,
 *      fragment tricks, IP literals, localhost variants) are blocked.
 */
public class InfrastructureVulnsTest {

    private InfrastructureVulns vulns;
    private HttpServletRequest mockRequest;

    @BeforeEach
    void setUp() {
        vulns = new InfrastructureVulns();
        mockRequest = Mockito.mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // Helper — set the "url" request parameter
    // -----------------------------------------------------------------------
    private void setUrlParam(String url) {
        Mockito.when(mockRequest.getParameter("url")).thenReturn(url);
    }

    // -----------------------------------------------------------------------
    // 1. Disallowed-host attacks must throw SecurityException
    // -----------------------------------------------------------------------

    /**
     * Attacker supplies an internal/metadata endpoint.
     * Without the fix, this would reach the AWS metadata service.
     */
    @Test
    void ssrf_internalAwsMetadata_shouldThrowSecurityException() {
        setUrlParam("http://169.254.169.254/latest/meta-data/");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Requests to the AWS metadata service must be blocked");
    }

    /**
     * Attacker targets localhost to probe internal services.
     */
    @Test
    void ssrf_localhost_shouldThrowSecurityException() {
        setUrlParam("http://localhost:8080/admin");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Requests to localhost must be blocked");
    }

    /**
     * Attacker uses 127.0.0.1 directly instead of the 'localhost' hostname.
     */
    @Test
    void ssrf_loopbackIp_shouldThrowSecurityException() {
        setUrlParam("http://127.0.0.1/secret");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Requests to 127.0.0.1 must be blocked");
    }

    /**
     * Attacker targets an RFC 1918 private network address.
     */
    @Test
    void ssrf_privateNetwork_shouldThrowSecurityException() {
        setUrlParam("http://192.168.1.1/");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Requests to private-network IPs must be blocked");
    }

    /**
     * Attacker uses an arbitrary external host not on the allowlist.
     */
    @Test
    void ssrf_arbitraryExternalHost_shouldThrowSecurityException() {
        setUrlParam("http://evil.attacker.com/steal");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Requests to hosts not on the allowlist must be blocked");
    }

    // -----------------------------------------------------------------------
    // 2. Disallowed-scheme attacks must throw SecurityException
    // -----------------------------------------------------------------------

    /**
     * Attacker uses file:// to read local files from the server filesystem.
     */
    @Test
    void ssrf_fileScheme_shouldThrowSecurityException() {
        setUrlParam("file:///etc/passwd");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "file:// URLs must be blocked");
    }

    /**
     * Attacker uses ftp:// to bypass HTTP-only network rules.
     */
    @Test
    void ssrf_ftpScheme_shouldThrowSecurityException() {
        setUrlParam("ftp://trusted.example.com/data");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "ftp:// URLs must be blocked even for allowed hosts");
    }

    // -----------------------------------------------------------------------
    // 3. Bypass attempts using userinfo / authority tricks
    // -----------------------------------------------------------------------

    /**
     * Attacker embeds the allowed host in the userinfo portion of the URL
     * (e.g., http://trusted.example.com@evil.com/), hoping string-match
     * validation checks the wrong part of the URL.
     * java.net.URI.getHost() returns "evil.com" for this input.
     */
    @Test
    void ssrf_userinfoBypass_shouldThrowSecurityException() {
        // URI: userinfo = "trusted.example.com", host = "evil.com"
        setUrlParam("http://trusted.example.com@evil.com/");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Userinfo-based bypass attempts must be blocked");
    }

    /**
     * Attacker appends the allowed hostname as a subdomain of a malicious host.
     */
    @Test
    void ssrf_subdomainBypass_shouldThrowSecurityException() {
        setUrlParam("http://trusted.example.com.evil.com/");
        assertThrows(SecurityException.class, () -> vulns.fetchUrl(mockRequest),
                "Subdomain bypass attempts must be blocked");
    }

    // -----------------------------------------------------------------------
    // 4. Null / blank / malformed input
    // -----------------------------------------------------------------------

    /**
     * A null parameter (parameter not present) must not reach the network.
     * The URI constructor will throw NullPointerException or the code will
     * throw SecurityException — either way no connection is made.
     */
    @Test
    void ssrf_nullUrl_shouldThrow() {
        setUrlParam(null);
        assertThrows(Exception.class, () -> vulns.fetchUrl(mockRequest),
                "A null URL must not result in a network connection");
    }

    /**
     * Malformed URLs should be rejected before any connection attempt.
     */
    @Test
    void ssrf_malformedUrl_shouldThrow() {
        setUrlParam("not a url at all");
        assertThrows(Exception.class, () -> vulns.fetchUrl(mockRequest),
                "A malformed URL must not result in a network connection");
    }

    // -----------------------------------------------------------------------
    // 5. Positive / regression tests — allowed hosts must work
    //    (these will fail with a connection error at network I/O time in a
    //     unit-test context, but they must NOT throw SecurityException,
    //     demonstrating the allowlist itself permits the call to proceed)
    // -----------------------------------------------------------------------

    /**
     * A URL whose host is on the allowlist should pass security validation
     * (a connection error is expected in a unit-test environment without a
     * live network, so we assert on the exception type — anything other than
     * SecurityException means the allowlist accepted the host).
     */
    @Test
    void fetchUrl_allowedHost_passesSecurityValidation() {
        setUrlParam("https://trusted.example.com/resource");
        // In a unit-test context there is no live network, so we expect some
        // IOException (or similar) from the actual connection attempt — but
        // NOT a SecurityException, which would mean the allowlist rejected it.
        Exception thrown = assertThrows(Exception.class, () -> vulns.fetchUrl(mockRequest));
        assertFalse(thrown instanceof SecurityException,
                "An allowed host must not be rejected by the SSRF allowlist; got: " + thrown);
    }

    /**
     * The second allowed host must also pass security validation.
     */
    @Test
    void fetchUrl_secondAllowedHost_passesSecurityValidation() {
        setUrlParam("https://api.example.com/data");
        Exception thrown = assertThrows(Exception.class, () -> vulns.fetchUrl(mockRequest));
        assertFalse(thrown instanceof SecurityException,
                "An allowed host must not be rejected by the SSRF allowlist; got: " + thrown);
    }
}
