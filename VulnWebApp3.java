import javax.servlet.http.HttpServletRequest;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

public class CriticalVulnerabilities {

    // Allowlist of permitted commands. Only exact matches are accepted;
    // no shell metacharacters or arguments can be injected through this set.
    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new java.util.HashSet<>(Arrays.asList("date", "uptime", "hostname")));

    // 1. SQL Injection (High/Critical)
    public void searchUser(HttpServletRequest request) throws Exception {

        String username = request.getParameter("username");

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test",
                "user",
                "pass");

        Statement stmt = conn.createStatement();

        stmt.executeQuery(
                "SELECT * FROM users WHERE username='"
                        + username + "'");
    }

    // 2. Command Injection – FIXED
    // Previously: Runtime.getRuntime().exec(command) with raw user input → command injection.
    // Fix: validate "cmd" against a strict allowlist, then execute via ProcessBuilder with an
    // argv list (no shell involved), so no shell metacharacters can be injected.
    public void execute(HttpServletRequest request)
            throws Exception {

        String command = request.getParameter("cmd");

        // Reject any value that is not in the hardcoded allowlist.
        // ProcessBuilder receives the command as a single argv element with no shell,
        // which is the SAST-recognized safe form for command execution.
        if (command == null || !ALLOWED_COMMANDS.contains(command)) {
            throw new IllegalArgumentException("Command not permitted: " + command);
        }

        // Use ProcessBuilder with an argv list – no shell interpolation occurs.
        List<String> argv = Collections.singletonList(command);
        new ProcessBuilder(argv).start();
    }

    // 3. SSRF (High)
    public String fetch(HttpServletRequest request)
            throws Exception {

        String target =
                request.getParameter("url");

        return new String(
                new URL(target)
                        .openStream()
                        .readAllBytes());
    }

    // 4. XXE (High)
    public Document parse(InputStream xml)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();

        DocumentBuilder builder =
                factory.newDocumentBuilder();

        return builder.parse(xml);
    }

    // 5. LDAP Injection (High)
    public void ldapSearch(HttpServletRequest request)
            throws Exception {

        String user =
                request.getParameter("user");

        Hashtable<String, String> env =
                new Hashtable<>();

        DirContext ctx =
                new InitialDirContext(env);

        ctx.search(
                "dc=test,dc=com",
                "(uid=" + user + ")",
                null);
    }

    // 6. Path Traversal – FIXED (CWE-23)
    // Previously: user-supplied "file" parameter was concatenated directly into
    // the path, allowing "../" sequences to escape /app/data/.
    // Fix: resolve the user-supplied name against the canonical base directory,
    // then call normalize() to collapse any ".." segments, and verify the result
    // is still within the allowed base before reading.  This is the
    // stdlib-native containment check recognised by SAST engines.
    private static final Path BASE_DIR = Paths.get("/app/data").normalize();

    public byte[] readFile(HttpServletRequest request)
            throws Exception {

        String file = request.getParameter("file");

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Missing 'file' parameter");
        }

        // Resolve the supplied name against the base directory and normalize
        // (collapses ".." and "." segments without requiring the path to exist).
        Path resolved = BASE_DIR.resolve(file).normalize();

        // Containment check: the canonical resolved path must still start with
        // the base directory.  Any traversal attempt (e.g. "../../etc/passwd")
        // produces a path outside BASE_DIR and is rejected here.
        if (!resolved.startsWith(BASE_DIR)) {
            throw new IOException("Access denied: path escapes the base directory");
        }

        return java.nio.file.Files.readAllBytes(resolved);
    }
}