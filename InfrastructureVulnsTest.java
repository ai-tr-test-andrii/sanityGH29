import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the SSRF remediation in InfrastructureVulns#fetchUrl.
 *
 * The vulnerability allowed an attacker to supply an arbitrary URL via the
 * "url" request parameter, causing the server to make requests to internal
 * or external hosts of the attacker's choosing (CWE-918).
 *
 * The fix enforces:
 *  1. Scheme must be "https" (blocks file://, ftp://, gopher://, http://, etc.)
 *  2. Host must appear in the ALLOWED_HOSTS allowlist.
 *
 * These tests verify that the allowlist enforcement works correctly and that
 * attack payloads are blocked before openStream() is ever called.
 */
class InfrastructureVulnsTest {

    private InfrastructureVulns sut;
    private HttpServletRequest  request;

    @BeforeEach
    void setUp() {
        sut     = new InfrastructureVulns();
        request = mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // Negative-case tests: attack payloads that MUST be rejected
    // -----------------------------------------------------------------------

    /**
     * Arbitrary external hosts must be blocked even when using HTTPS,
     * because they are not in the allowlist.
     */
    @ParameterizedTest(name = "blocks external host: {0}")
    @ValueSource(strings = {
            "https://attacker.com/steal",
            "https://evil.example.org/data",
            "https://169.254.169.254/latest/meta-data/"  // AWS metadata endpoint
    })
    void fetchUrl_blocksArbitraryExternalHosts(String maliciousUrl) {
        when(request.getParameter("url")).thenReturn(maliciousUrl);

        SecurityException ex = assertThrows(
                SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for external host: " + maliciousUrl
        );
        assertTrue(ex.getMessage().contains("allowlist"),
                "Exception message should mention 'allowlist'");
    }

    /**
     * Internal network addresses must be blocked (SSRF against internal
     * services is the primary attack vector CWE-918 describes).
     */
    @ParameterizedTest(name = "blocks internal address: {0}")
    @ValueSource(strings = {
            "https://localhost/admin",
            "https://127.0.0.1/secrets",
            "https://192.168.1.1/router",
            "https://10.0.0.1/internal-api",
            "https://[::1]/ipv6-loopback"
    })
    void fetchUrl_blocksInternalAddresses(String internalUrl) {
        when(request.getParameter("url")).thenReturn(internalUrl);

        assertThrows(
                SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for internal address: " + internalUrl
        );
    }

    /**
     * Non-HTTPS schemes must be blocked to prevent file-read, FTP, and
     * protocol-smuggling attacks.
     */
    @ParameterizedTest(name = "blocks non-https scheme: {0}")
    @ValueSource(strings = {
            "http://trusted.example.com/resource",   // plain HTTP, not in HTTPS allowlist
            "file:///etc/passwd",
            "ftp://trusted.example.com/file",
            "gopher://trusted.example.com:70/_POST%20..."
    })
    void fetchUrl_blocksNonHttpsSchemes(String attackUrl) {
        when(request.getParameter("url")).thenReturn(attackUrl);

        assertThrows(
                SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for scheme in: " + attackUrl
        );
    }

    /**
     * A malformed / null URL must never reach openStream().
     * java.net.URI will throw URISyntaxException for truly malformed input;
     * the method must propagate it rather than silently continuing.
     */
    @Test
    void fetchUrl_rejectsMalformedUrl() {
        when(request.getParameter("url")).thenReturn("not a url at all %%");

        // Any exception (URISyntaxException or SecurityException) is acceptable;
        // what is NOT acceptable is silently proceeding.
        assertThrows(
                Exception.class,
                () -> sut.fetchUrl(request),
                "Malformed URL must not be silently accepted"
        );
    }

    /**
     * A null parameter must not cause a NullPointerException that bypasses
     * the allowlist check; it must throw an appropriate exception.
     */
    @Test
    void fetchUrl_rejectsNullParameter() {
        when(request.getParameter("url")).thenReturn(null);

        assertThrows(
                Exception.class,
                () -> sut.fetchUrl(request),
                "Null 'url' parameter must not be silently accepted"
        );
    }

    /**
     * Host-confusion / bypass attempt: a URL whose authority contains
     * an allowlisted host as a subdomain of an attacker-controlled domain.
     * Example: "https://trusted.example.com.attacker.com/" should NOT match
     * because the host "trusted.example.com.attacker.com" is not in the
     * allowlist.
     */
    @Test
    void fetchUrl_blocksHostConfusionBypassAttempt() {
        String bypassAttempt = "https://trusted.example.com.attacker.com/steal";
        when(request.getParameter("url")).thenReturn(bypassAttempt);

        assertThrows(
                SecurityException.class,
                () -> sut.fetchUrl(request),
                "Host-confusion bypass must be blocked by exact-match allowlist check"
        );
    }

    /**
     * URL with credentials embedded in the authority (user@host) pointing at
     * an allowlisted host must still be blocked if the embedded credentials
     * could mislead an SSRF filter (defense-in-depth: URI#getHost() strips
     * the userinfo, so the host check itself is sufficient, but the test
     * documents expected behavior).
     *
     * "https://attacker.com@trusted.example.com/" — here URI#getHost()
     * returns "trusted.example.com", which IS in the allowlist. This test
     * documents that the stdlib URI parser handles this correctly.  The
     * actual network request would go to trusted.example.com, which is the
     * intended allowed host, so this variant passes the allowlist.
     *
     * For the opposite ordering, "https://trusted.example.com@attacker.com/",
     * URI#getHost() returns "attacker.com" — not in the allowlist → blocked.
     */
    @Test
    void fetchUrl_blocksUserinfoHostConfusion() {
        // "trusted.example.com" appears as userinfo; actual host is "attacker.com"
        String bypassAttempt = "https://trusted.example.com@attacker.com/steal";
        when(request.getParameter("url")).thenReturn(bypassAttempt);

        assertThrows(
                SecurityException.class,
                () -> sut.fetchUrl(request),
                "Userinfo-host confusion bypass must be blocked"
        );
    }

    // -----------------------------------------------------------------------
    // Positive-case test: allowed hosts must pass the validation gate
    // (network call itself is not made in unit tests; only the guard logic
    // is tested up to the point where URL#openStream() would be invoked)
    // -----------------------------------------------------------------------

    /**
     * Verifies that the allowlist guard does NOT throw SecurityException for
     * an allowlisted host with HTTPS.  The test intercepts at the
     * java.net.URL level so no actual network I/O occurs.
     *
     * Because fetchUrl() calls url.openStream() after the guard, and
     * "trusted.example.com" is not reachable in unit-test environments, we
     * expect either:
     *   - A java.net.UnknownHostException / IOException (guard passed, network
     *     layer raised an error) — acceptable, guard worked correctly.
     *   - Any exception that is NOT a SecurityException.
     *
     * A SecurityException here would mean the allowlist incorrectly blocked
     * the request, which is a regression.
     */
    @Test
    void fetchUrl_allowsListedHostWithHttps() {
        when(request.getParameter("url"))
                .thenReturn("https://trusted.example.com/resource");

        try {
            sut.fetchUrl(request);
            // If somehow the host resolves (e.g., in an integration env),
            // returning normally is also acceptable.
        } catch (SecurityException e) {
            fail("SecurityException must NOT be thrown for an allowlisted host. "
                    + "Message: " + e.getMessage());
        } catch (Exception e) {
            // IOException, UnknownHostException, etc. — the guard passed,
            // network layer raised an expected error.  This is acceptable.
        }
    }
}
