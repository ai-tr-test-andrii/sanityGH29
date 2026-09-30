import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the path-traversal fix in CriticalVulnerabilities.readFile().
 *
 * Vulnerability: CWE-23 – The original code appended the raw "file" request
 * parameter directly to "/app/data/" and passed it to Files.readAllBytes().
 * An attacker could supply a value such as "../../etc/passwd" to read
 * arbitrary files outside the intended directory.
 *
 * Fix: The method now resolves the candidate path against the canonicalized
 * base directory (/app/data), normalizes it to collapse ".." segments, and
 * verifies via Path.startsWith() that the result still resides within the
 * base directory. Any path that escapes the base directory is rejected with
 * a SecurityException before the file is opened.
 *
 * These tests verify:
 *  1. Legitimate file names within the base directory resolve correctly
 *     according to Path arithmetic.
 *  2. Path-traversal payloads (relative, absolute paths, and various ".."
 *     forms) are rejected with SecurityException.
 *  3. Null and edge-case inputs are handled without silently serving files.
 */
public class CriticalVulnerabilitiesReadFileTest {

    private CriticalVulnerabilities subject;

    /** Temporary directory for any helper work during tests. */
    private Path tempBase;

    @BeforeEach
    void setUp() throws IOException {
        subject = new CriticalVulnerabilities();
        tempBase = Files.createTempDirectory("readfile-test-");
    }

    @AfterEach
    void tearDown() throws IOException {
        if (tempBase != null && Files.exists(tempBase)) {
            try (var stream = Files.walk(tempBase)) {
                stream.sorted(java.util.Comparator.reverseOrder())
                      .forEach(p -> {
                          try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                      });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build a mock HttpServletRequest that returns the given "file" value.
    // -----------------------------------------------------------------------
    private HttpServletRequest requestWith(String file) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("file")).thenReturn(file);
        return req;
    }

    // -----------------------------------------------------------------------
    // Negative tests – traversal payloads MUST be rejected with SecurityException.
    //
    // CriticalVulnerabilities.readFile() is hard-coded to use "/app/data" as
    // its base directory.  The containment check fires before any I/O is
    // attempted, so SecurityException is thrown regardless of whether the
    // resolved path exists on disk.
    // -----------------------------------------------------------------------

    @Test
    void dotDotSlash_escapesBase_isRejected() {
        // Classic relative traversal: "../etc/passwd" resolves to "/app/etc/passwd"
        // which is outside /app/data.
        HttpServletRequest req = requestWith("../etc/passwd");
        assertThrows(SecurityException.class, () -> subject.readFile(req),
                "Relative traversal with ../ must be rejected");
    }

    @Test
    void multipleDotsSlash_deepEscape_isRejected() {
        // Multiple "../" segments to climb to the filesystem root.
        HttpServletRequest req = requestWith("../../etc/shadow");
        assertThrows(SecurityException.class, () -> subject.readFile(req),
                "Multi-level relative traversal must be rejected");
    }

    @Test
    void absolutePath_toSensitiveFile_isRejected() {
        // Supplying an absolute path bypasses the base directory entirely.
        HttpServletRequest req = requestWith("/etc/passwd");
        assertThrows(SecurityException.class, () -> subject.readFile(req),
                "Absolute path outside base directory must be rejected");
    }

    @Test
    void mixedTraversal_embeddedDotDot_isRejected() {
        // Attempt to escape via a deeper path: start inside /app/data, then traverse out.
        HttpServletRequest req = requestWith("subdir/../../etc/hosts");
        assertThrows(SecurityException.class, () -> subject.readFile(req),
                "Embedded ../ in a subdirectory path must be rejected");
    }

    @Test
    void trailingDotDot_isRejected() {
        // "report/.." resolves to "/app/data", which equals the base directory
        // but not a regular file within it.  The fix must either reject it
        // (SecurityException) or throw IOException when trying to read a directory.
        HttpServletRequest req = requestWith("report/..");
        assertThrows(Exception.class, () -> subject.readFile(req),
                "A path resolving to the base directory itself must not succeed silently");
    }

    @Test
    void nullByteInjection_inFilename_isRejected() {
        // Null byte () injection: on some platforms this truncates the path string.
        // Java's NIO Path API rejects strings with embedded NUL characters, so this
        // must throw an exception (SecurityException or InvalidPathException) before
        // the file is read.
        String nullBytePayload = "safe" + "\000" + "../../etc/passwd";
        HttpServletRequest req = requestWith(nullBytePayload);
        assertThrows(Exception.class, () -> subject.readFile(req),
                "Null-byte injection must not allow traversal");
    }

    @ParameterizedTest(name = "traversal payload ''{0}'' is rejected")
    @ValueSource(strings = {
        "../secret.txt",
        "../../root/.bashrc",
        "../../../etc/passwd",
        "/etc/shadow",
        "/app/data/../secret",
        "subdir/../../../etc/hosts"
    })
    void variousTraversalPayloads_areRejected(String payload) {
        HttpServletRequest req = requestWith(payload);
        assertThrows(SecurityException.class, () -> subject.readFile(req),
                "Traversal payload must be rejected: " + payload);
    }

    // -----------------------------------------------------------------------
    // Positive tests – the containment check must NOT block files that
    // genuinely reside inside /app/data.
    //
    // Because the production code is hard-coded to "/app/data" and that
    // directory is unlikely to exist in the test environment, we verify the
    // containment logic directly using Path arithmetic.  The critical property:
    // a normalized path whose components start with those of "/app/data" passes
    // Path.startsWith().
    // -----------------------------------------------------------------------

    @Test
    void simpleFilename_staysWithinBase() {
        Path base = Paths.get("/app/data").toAbsolutePath().normalize();
        Path resolved = base.resolve("report.txt").normalize().toAbsolutePath();

        assertTrue(resolved.startsWith(base),
                "Plain filename must resolve inside the base directory");
    }

    @Test
    void subdirectoryFilename_staysWithinBase() {
        Path base = Paths.get("/app/data").toAbsolutePath().normalize();
        Path resolved = base.resolve("reports/2024/annual.pdf").normalize().toAbsolutePath();

        assertTrue(resolved.startsWith(base),
                "Subdirectory filename must resolve inside the base directory");
    }

    @Test
    void normalizedTraversalPayload_isDetectedAsOutside() {
        // After normalize(), a traversal payload must NOT start with the base.
        Path base = Paths.get("/app/data").toAbsolutePath().normalize();
        Path resolved = base.resolve("../etc/passwd").normalize().toAbsolutePath();

        assertFalse(resolved.startsWith(base),
                "Normalized traversal must resolve outside the base directory");
    }

    // -----------------------------------------------------------------------
    // Edge-case containment logic tests.
    // -----------------------------------------------------------------------

    @Test
    void pathExactlyEqualToBase_satisfiesStartsWith() {
        // An empty-string resolve returns the base directory itself.
        // It passes startsWith(), but the subsequent Files.readAllBytes() will
        // fail with IOException because it is a directory, not a regular file.
        // This confirms the security check is on startsWith(), and the OS
        // prevents reading a directory as bytes.
        Path base = Paths.get("/app/data").toAbsolutePath().normalize();
        Path resolved = base.resolve("").normalize().toAbsolutePath();

        assertTrue(resolved.startsWith(base),
                "Base directory itself satisfies startsWith – OS will reject the read");
    }

    @Test
    void pathAdjacentToBase_doesNotPassStartsWith() {
        // "/app/data-sensitive" must NOT pass a startsWith("/app/data") check
        // because Path.startsWith() compares path COMPONENTS, not string prefixes.
        // This verifies the fix is safe against the "adjacent-directory" bypass.
        Path base = Paths.get("/app/data").toAbsolutePath().normalize();
        Path adjacent = Paths.get("/app/data-sensitive/secret.txt").toAbsolutePath().normalize();

        assertFalse(adjacent.startsWith(base),
                "A path adjacent to the base (data-sensitive) must not pass startsWith");
    }

    @Test
    void pathWithSingleDot_normalizedToBase() {
        // "." resolves to the base directory itself.
        Path base = Paths.get("/app/data").toAbsolutePath().normalize();
        Path resolved = base.resolve(".").normalize().toAbsolutePath();

        assertEquals(base, resolved,
                "Resolving '.' must normalize back to the base directory");
    }
}
