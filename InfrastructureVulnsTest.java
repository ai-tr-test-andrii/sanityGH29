import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the SSRF remediation in InfrastructureVulns#fetchUrl.
 *
 * The fix validates the user-supplied URL against an allowlist of permitted
 * hosts and enforces HTTPS-only before any outbound connection is attempted.
 * These tests verify that disallowed destinations are rejected *before* the
 * openStream() sink is reached — i.e., no network traffic is ever initiated
 * for blocked inputs.
 */
public class InfrastructureVulnsTest {

    private InfrastructureVulns sut;
    private HttpServletRequest  request;

    @BeforeEach
    void setUp() {
        sut     = new InfrastructureVulns();
        request = Mockito.mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // Negative tests — attacker-controlled inputs must be blocked
    // -----------------------------------------------------------------------

    /**
     * An arbitrary external host that is not in the allowlist must be
     * rejected with a SecurityException so that openStream() is never called.
     */
    @Test
    void fetchUrl_blocksArbitraryExternalHost() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("https://attacker.example.com/evil");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for non-allowlisted host");
    }

    /**
     * Internal network addresses (RFC-1918 ranges) commonly used for
     * metadata service attacks must be rejected.
     */
    @Test
    void fetchUrl_blocksInternalNetworkAddress() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("https://192.168.1.1/admin");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for internal network address");
    }

    /**
     * The AWS metadata endpoint (http://169.254.169.254) is a classic SSRF
     * target.  Both the non-HTTPS scheme and the non-allowlisted host should
     * trigger rejection.
     */
    @Test
    void fetchUrl_blocksAwsMetadataEndpoint() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("http://169.254.169.254/latest/meta-data/");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for AWS metadata endpoint");
    }

    /**
     * Plain HTTP (non-HTTPS) must be rejected even if the host would otherwise
     * be on the allowlist — the fix requires both scheme=HTTPS and allowlisted
     * host.
     */
    @Test
    void fetchUrl_blocksHttpSchemeForAllowlistedHost() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("http://trusted-api.example.com/data");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for HTTP (non-HTTPS) scheme");
    }

    /**
     * A URL using the file:// scheme must be rejected; such a request could
     * read arbitrary files from the server's filesystem.
     */
    @Test
    void fetchUrl_blocksFileScheme() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("file:///etc/passwd");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for file:// scheme");
    }

    /**
     * A URL using the ftp:// scheme must be rejected.
     */
    @Test
    void fetchUrl_blocksFtpScheme() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("ftp://internal-server.corp/secret.txt");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for ftp:// scheme");
    }

    /**
     * A URL that embeds credentials in the authority component
     * (userinfo@host) should not fool the host extraction step — the host
     * part alone must still fail the allowlist check.
     */
    @Test
    void fetchUrl_blocksUrlWithEmbeddedCredentials() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("https://trusted-api.example.com@attacker.example.com/");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for URL with embedded credentials pointing to non-allowlisted host");
    }

    /**
     * localhost (loopback) is not in the allowlist and must be rejected.
     */
    @Test
    void fetchUrl_blocksLocalhost() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("https://localhost/admin");

        assertThrows(SecurityException.class,
                () -> sut.fetchUrl(request),
                "Expected SecurityException for localhost");
    }

    /**
     * A completely empty or null URL parameter should result in an exception
     * (either SecurityException or a parsing exception), not a successful
     * outbound connection.
     */
    @Test
    void fetchUrl_blocksNullUrl() {
        Mockito.when(request.getParameter("url"))
               .thenReturn(null);

        assertThrows(Exception.class,
                () -> sut.fetchUrl(request),
                "Expected an exception for a null URL parameter");
    }

    /**
     * An empty-string URL must not result in an outbound connection.
     */
    @Test
    void fetchUrl_blocksEmptyUrl() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("");

        assertThrows(Exception.class,
                () -> sut.fetchUrl(request),
                "Expected an exception for an empty URL parameter");
    }

    // -----------------------------------------------------------------------
    // Positive structural tests — allowlisted hosts pass validation
    // (actual network I/O is NOT exercised; a SecurityException must NOT be
    //  thrown for a well-formed HTTPS URL with an allowlisted host)
    // -----------------------------------------------------------------------

    /**
     * A well-formed HTTPS URL whose host is in the allowlist must NOT be
     * rejected by the security guard itself.  A real network call would
     * follow, which is expected to fail in a unit-test environment with a
     * connection error — but the all-important SecurityException must NOT
     * be thrown.
     *
     * This test directly exercises the sink path (openStream) and confirms
     * only network-level errors occur — not a security block.
     */
    @Test
    void fetchUrl_allowsAllowlistedHttpsHost() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("https://trusted-api.example.com/resource");

        // The security check should PASS — the subsequent openStream() will
        // fail with a connectivity / DNS error in a unit test, not a
        // SecurityException.  We assert that the exception thrown is NOT a
        // SecurityException.
        Exception thrown = assertThrows(Exception.class,
                () -> sut.fetchUrl(request),
                "Expected a connectivity exception (not a SecurityException) for an allowlisted URL");

        assertFalse(thrown instanceof SecurityException,
                "SecurityException must NOT be thrown for an allowlisted HTTPS host; "
                + "got: " + thrown.getClass().getName());
    }

    /**
     * The second allowlisted host ("cdn.example.com") should also pass the
     * security guard without throwing a SecurityException.
     */
    @Test
    void fetchUrl_allowsSecondAllowlistedHost() {
        Mockito.when(request.getParameter("url"))
               .thenReturn("https://cdn.example.com/image.png");

        Exception thrown = assertThrows(Exception.class,
                () -> sut.fetchUrl(request));

        assertFalse(thrown instanceof SecurityException,
                "SecurityException must NOT be thrown for cdn.example.com; "
                + "got: " + thrown.getClass().getName());
    }
}
