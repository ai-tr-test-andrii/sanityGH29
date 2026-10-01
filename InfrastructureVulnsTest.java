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

    // -----------------------------------------------------------------------
    // 6. Weak hash (CWE-327) remediation tests
    //    The md5() method was replaced with hash() which uses SHA-256.
    //    These tests verify:
    //      a) The method no longer uses MD5.
    //      b) The output length is 32 bytes (SHA-256 digest size).
    //      c) The digest matches the expected SHA-256 value for known inputs.
    //      d) MD5 would produce a different (shorter) output, confirming the
    //         algorithm was actually changed.
    // -----------------------------------------------------------------------

    /**
     * SHA-256 digest of "hello" must be 32 bytes (256 bits).
     * MD5 produces only 16 bytes — a different length conclusively proves
     * the algorithm is no longer MD5.
     */
    @Test
    void hash_outputLength_is32Bytes() throws Exception {
        byte[] digest = vulns.hash("hello");
        assertEquals(32, digest.length,
                "SHA-256 digest must be 32 bytes; MD5 produces only 16 — wrong algorithm in use");
    }

    /**
     * Verify the digest of "hello" matches the well-known SHA-256 value.
     * This directly exercises the MessageDigest.getInstance("SHA-256") sink
     * introduced by the fix and confirms the algorithm is SHA-256, not MD5.
     *
     * SHA-256("hello") =
     *   2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
     */
    @Test
    void hash_knownInput_matchesSha256() throws Exception {
        String expectedHex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        byte[] digest = vulns.hash("hello");
        // Convert byte array to lowercase hex for comparison
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        assertEquals(expectedHex, sb.toString(),
                "Digest must equal the canonical SHA-256 value for 'hello'");
    }

    /**
     * SHA-256 of an empty string must equal the well-known value.
     * Exercises the edge case of a zero-length input.
     *
     * SHA-256("") =
     *   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     */
    @Test
    void hash_emptyString_matchesSha256() throws Exception {
        String expectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        byte[] digest = vulns.hash("");
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        assertEquals(expectedHex, sb.toString(),
                "Digest of empty string must equal the canonical SHA-256 value");
    }

    /**
     * Regression: confirm the output is NOT the MD5 digest of "hello".
     * MD5("hello") = 5d41402abc4b2a76b9719d911017c592
     * This test would FAIL if MD5 were still used, providing an explicit
     * regression guard against reintroducing the broken algorithm.
     */
    @Test
    void hash_output_doesNotMatchMd5() throws Exception {
        // MD5("hello") — kept as a hex literal to document the old broken value
        String md5OfHello = "5d41402abc4b2a76b9719d911017c592";
        byte[] digest = vulns.hash("hello");
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        assertNotEquals(md5OfHello, sb.toString(),
                "Output must NOT be the MD5 digest — MD5 must not be used");
    }

    /**
     * The same input always produces the same digest (determinism / idempotency).
     */
    @Test
    void hash_sameInput_producesSameDigest() throws Exception {
        byte[] first  = vulns.hash("repeatableInput");
        byte[] second = vulns.hash("repeatableInput");
        assertArrayEquals(first, second,
                "SHA-256 must be deterministic — the same input must always yield the same digest");
    }

    /**
     * Different inputs must produce different digests (collision resistance
     * property is expected for SHA-256 on these trivially distinct inputs).
     */
    @Test
    void hash_differentInputs_produceDifferentDigests() throws Exception {
        byte[] a = vulns.hash("inputA");
        byte[] b = vulns.hash("inputB");
        assertFalse(java.util.Arrays.equals(a, b),
                "Different inputs must produce different SHA-256 digests");
    }
}
