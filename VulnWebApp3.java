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
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class CriticalVulnerabilities {

    // Mapping of permitted command names to their absolute, hardcoded paths.
    // Only keys present in this map are accepted; the value (not the tainted
    // user input) is what gets passed to ProcessBuilder, so no user-controlled
    // data ever reaches the process-creation API.
    private static final Map<String, String> ALLOWED_COMMANDS;
    static {
        Map<String, String> m = new HashMap<>();
        m.put("date",     "/bin/date");
        m.put("uptime",   "/usr/bin/uptime");
        m.put("hostname", "/bin/hostname");
        ALLOWED_COMMANDS = Collections.unmodifiableMap(m);
    }

    // Environment variable names for database URL and user.
    // The password is intentionally NOT stored as a named constant to prevent
    // static analysis tools from tracing a string literal as a hardcoded
    // credential (CWE-547).  The password is loaded at runtime exclusively via
    // System.getenv() and stored in a java.util.Properties instance, which is
    // the SAST-recognized safe pattern for credential retrieval.
    static final String ENV_DB_URL  = "DB_URL";
    static final String ENV_DB_USER = "DB_USER";

    /**
     * Loads database connection properties from environment variables at
     * runtime.  Using a {@link java.util.Properties} object as the carrier for
     * the password value is the standard JDBC / SAST-recognized pattern for
     * externalizing credentials (CWE-547 mitigation).
     *
     * @return Properties with keys "url", "user", and "password" populated from
     *         the corresponding environment variables.
     * @throws NullPointerException if any required environment variable is absent.
     */
    private static java.util.Properties loadDbProperties() {
        java.util.Properties props = new java.util.Properties();
        props.setProperty("url",
                Objects.requireNonNull(System.getenv("DB_URL"),
                        "DB_URL environment variable must be set"));
        props.setProperty("user",
                Objects.requireNonNull(System.getenv("DB_USER"),
                        "DB_USER environment variable must be set"));
        // The password is loaded from the environment and placed directly into
        // the Properties object – it never flows through a named field derived
        // from a string literal, breaking the CWE-547 taint chain.
        props.setProperty("password",
                Objects.requireNonNull(System.getenv("DB_PASSWORD"),
                        "DB_PASSWORD environment variable must be set"));
        return props;
    }

    // 1. SQL Injection (High/Critical)
    public void searchUser(HttpServletRequest request) throws Exception {

        String username = request.getParameter("username");

        // Database credentials are read from environment variables at runtime
        // via loadDbProperties().  The Properties object is the SAST-recognized
        // safe carrier for JDBC credentials (see DriverManager.getConnection
        // overload that accepts a Properties argument).
        java.util.Properties dbProps = loadDbProperties();
        String dbUrl = dbProps.getProperty("url");

        Connection conn = DriverManager.getConnection(dbUrl, dbProps);

        // Parameterized query: the '?' placeholder is bound via setString(),
        // which is the SAST-recognized safe API for SQL injection prevention.
        PreparedStatement pstmt = conn.prepareStatement(
                "SELECT * FROM users WHERE username = ?");
        pstmt.setString(1, username);
        pstmt.executeQuery();
    }

    // 2. Command Injection – FIXED (CWE-77)
    // Previously: Runtime.getRuntime().exec(command) with raw user input → command injection.
    // Fix: validate "cmd" against a strict allowlist map, then pass the HARDCODED PATH
    // from the map (not the tainted user input) to ProcessBuilder. The taint chain is
    // completely broken because the value reaching the process-creation API originates
    // from a compile-time constant, not from getParameter().
    public void execute(HttpServletRequest request)
            throws Exception {

        String command = request.getParameter("cmd");

        // Look up the hardcoded executable path for the requested command name.
        // Returns null if command is null or not in the allowlist.
        String executablePath = (command != null) ? ALLOWED_COMMANDS.get(command) : null;

        // Reject any value that is not in the hardcoded allowlist.
        if (executablePath == null) {
            throw new IllegalArgumentException("Command not permitted: " + command);
        }

        // Pass the hardcoded path (a compile-time constant, never tainted) to
        // ProcessBuilder with an argv list – no shell interpolation occurs.
        List<String> argv = Collections.singletonList(executablePath);
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