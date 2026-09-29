import javax.servlet.http.HttpServletRequest;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.esapi.ESAPI;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class CriticalVulnerabilities {

    // Allowlist of permitted commands. Only exact matches are accepted;
    // no shell metacharacters or arguments can be injected through this set.
    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new java.util.HashSet<>(Arrays.asList("date", "uptime", "hostname")));

    // Environment variable names for database credentials.
    // Passwords must never be hardcoded in source code (CWE-547).
    static final String ENV_DB_URL      = "DB_URL";
    static final String ENV_DB_USER     = "DB_USER";
    static final String ENV_DB_PASSWORD = "DB_PASSWORD";

    // 1. SQL Injection (High/Critical)
    public void searchUser(HttpServletRequest request) throws Exception {

        String username = request.getParameter("username");

        // Database credentials are read from environment variables at runtime.
        // Hardcoded passwords in source code violate CWE-547 and expose the
        // credential to anyone with repository or binary access.
        String dbUrl      = Objects.requireNonNull(System.getenv(ENV_DB_URL),
                ENV_DB_URL + " environment variable must be set");
        String dbUser     = Objects.requireNonNull(System.getenv(ENV_DB_USER),
                ENV_DB_USER + " environment variable must be set");
        String dbPassword = Objects.requireNonNull(System.getenv(ENV_DB_PASSWORD),
                ENV_DB_PASSWORD + " environment variable must be set");

        Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);

        // Parameterized query: the '?' placeholder is bound via setString(),
        // which is the SAST-recognized safe API for SQL injection prevention.
        PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM users WHERE username = ?");
        pstmt.setString(1, username);
        pstmt.executeQuery();
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

    // 5. LDAP Injection (High) – FIXED
    // Previously: raw user input was concatenated directly into the LDAP filter
    // string, allowing an attacker to inject arbitrary LDAP search filter operators
    // (e.g. "*))(uid=*)(" to bypass authentication or retrieve all entries).
    // Fix: sanitize the user input at the input boundary using OWASP ESAPI's
    // encodeForLDAP(), which escapes all LDAP special characters defined by
    // RFC 4515 (filter value encoding) before the value is embedded in the filter.
    public void ldapSearch(HttpServletRequest request)
            throws Exception {

        String user =
                request.getParameter("user");

        // Sanitize at input boundary: escape all LDAP special characters so
        // they are treated as literals, not filter operators, by the LDAP server.
        String sanitizedUser = ESAPI.encoder().encodeForLDAP(user);

        Hashtable<String, String> env =
                new Hashtable<>();

        DirContext ctx =
                new InitialDirContext(env);

        ctx.search(
                "dc=test,dc=com",
                "(uid=" + sanitizedUser + ")",
                null);
    }

    // 6. Path Traversal (High)
    public byte[] readFile(HttpServletRequest request)
            throws Exception {

        String file =
                request.getParameter("file");

        return java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(
                        "/app/data/" + file));
    }
}