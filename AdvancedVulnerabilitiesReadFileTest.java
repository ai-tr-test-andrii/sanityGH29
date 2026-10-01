import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the Path Traversal fix in AdvancedVulnerabilities.readFile().
 *
 * The vulnerability (CWE-23) allowed an attacker to supply a "file" parameter
 * containing ".." sequences that escaped the "/tmp/" base directory. The fix
 * resolves and normalizes the path then checks that the result starts with the
 * base directory before performing any file I/O.
 */
public class AdvancedVulnerabilitiesReadFileTest {

    private AdvancedVulnerabilities subject;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        subject = new AdvancedVulnerabilities();
        request = mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------
    // Happy-path: valid file inside /tmp should be readable
    // -----------------------------------------------------------------

    @Test
    void readFile_validFilename_returnsFileContents(@TempDir Path tmpDir) throws Exception {
        // Write a known file under the system's real /tmp (or the JVM temp dir
        // registered as /tmp in this process). We create it via Files so the
        // path is definitely within base "/tmp".
        Path testFile = Files.createTempFile("readfile_test_", ".txt");
        byte[] expected = "hello world".getBytes();
        Files.write(testFile, expected);

        // The parameter is just the file name, no directory component.
        when(request.getParameter("file")).thenReturn(testFile.getFileName().toString());

        // Supply the correct base by placing the file in /tmp (its parent).
        // For portability in environments where /tmp resolves differently we
        // test the path the fix actually resolves against.
        byte[] result = subject.readFile(request);
        assertArrayEquals(expected, result);

        Files.deleteIfExists(testFile);
    }

    // -----------------------------------------------------------------
    // Security: path traversal attempts MUST be rejected
    // -----------------------------------------------------------------

    @Test
    void readFile_dotDotTraversal_throwsSecurityException() {
        // Classic "../" traversal to escape /tmp
        when(request.getParameter("file")).thenReturn("../etc/passwd");

        assertThrows(SecurityException.class, () -> subject.readFile(request));
    }

    @Test
    void readFile_absolutePathOutsideBase_throwsSecurityException() {
        // Absolute path to a sensitive location
        when(request.getParameter("file")).thenReturn("/etc/shadow");

        assertThrows(SecurityException.class, () -> subject.readFile(request));
    }

    @Test
    void readFile_encodedDotDotTraversal_throwsSecurityException() {
        // Multiple ".." segments that still escape /tmp after normalization
        when(request.getParameter("file")).thenReturn("subdir/../../etc/hosts");

        assertThrows(SecurityException.class, () -> subject.readFile(request));
    }

    @Test
    void readFile_trailingDotsOnly_throwsSecurityException() {
        // Edge case: just ".." with no following component
        when(request.getParameter("file")).thenReturn("..");

        assertThrows(SecurityException.class, () -> subject.readFile(request));
    }

    @Test
    void readFile_deepTraversal_throwsSecurityException() {
        // Many ".." segments trying to reach root
        when(request.getParameter("file")).thenReturn("../../../../../../../../etc/passwd");

        assertThrows(SecurityException.class, () -> subject.readFile(request));
    }

    // -----------------------------------------------------------------
    // Security: file that does not exist within /tmp → IOException,
    // NOT a traversal bypass (the SecurityException check must fire
    // BEFORE any I/O for out-of-bounds paths).
    // -----------------------------------------------------------------

    @Test
    void readFile_nonExistentFileInsideBase_throwsIOExceptionNotSecurityException() {
        // A file name that does NOT traverse out of /tmp but also does not exist.
        // The fix should not throw SecurityException (path is valid) — it should
        // instead let Files.readAllBytes throw a NoSuchFileException (subtype of
        // IOException) to preserve normal error handling.
        when(request.getParameter("file")).thenReturn("definitely_does_not_exist_xyz123.txt");

        assertThrows(IOException.class, () -> subject.readFile(request));
    }
}
