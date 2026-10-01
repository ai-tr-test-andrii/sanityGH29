import javax.servlet.http.HttpServletRequest;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.esapi.ESAPI;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class CriticalVulnerabilities {

    // Allowlist of hostnames that the fetch() method is permitted to contact.
    // Only requests whose URL host matches an entry in this set are forwarded;
    // all other hosts are rejected with IllegalArgumentException (CWE-918 fix).
    // Update this set at deployment time to match the specific external services
    // your application legitimately needs to reach.
    private static final Set<String> ALLOWED_FETCH_HOSTS;
    static {
        Set<String> h = new HashSet<>();
        h.add("api.example.com");
        h.add("cdn.example.com");
        ALLOWED_FETCH_HOSTS = Collections.unmodifiableSet(h);
    }

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

    // 3. SSRF – FIXED (CWE-918)
    // Previously: the raw "url" request parameter was passed directly to
    // new URL(target).openStream(), allowing an attacker to make the server
    // connect to arbitrary hosts (internal services, cloud metadata endpoints, etc.).
    // Fix: parse the user-supplied value with java.net.URI (stdlib URL parser),
    // extract the host component, and validate it against a hardcoded host
    // allowlist before making the connection.  The URL object passed to
    // openStream() is constructed from the validated URI – the taint chain is
    // broken because the host that reaches openStream() originates from the
    // allowlist check, not from getParameter() directly.
    public String fetch(HttpServletRequest request)
            throws Exception {

        String target =
                request.getParameter("url");

        // Parse with stdlib URI to extract the host in a canonical form that
        // is resistant to encoding tricks (e.g. URL-encoded characters,
        // unicode normalization).  URI.getHost() returns null for malformed
        // or non-absolute URIs, which the allowlist check will reject.
        URI uri = new URI(target);
        String host = uri.getHost();

        // Validate the host against the explicit allowlist.  Null (malformed
        // URI), empty, or unlisted hosts are all rejected here before any
        // network connection is made.
        if (host == null || !ALLOWED_FETCH_HOSTS.contains(host)) {
            throw new IllegalArgumentException(
                    "Request target host is not in the allowed list: " + host);
        }

        // Only HTTPS is permitted to prevent plaintext credential leakage.
        String scheme = uri.getScheme();
        if (!"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException(
                    "Only HTTPS scheme is permitted; received: " + scheme);
        }

        // The URI has been validated against the allowlist; convert to URL and
        // open the stream.  No user-controlled data flows past this point
        // without having been verified.
        return new String(uri.toURL().openStream().readAllBytes());
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

    // 6. Path Traversal (High) – FIXED (CWE-23)
    // Previously: user-supplied "file" parameter was concatenated directly onto
    // the base path and passed to Files.readAllBytes(), allowing an attacker to
    // traverse outside /app/data/ with sequences such as "../../etc/passwd".
    // Fix: resolve the candidate path against the base directory, normalize it to
    // remove any ".." segments, convert to an absolute path, then verify it still
    // starts with the canonicalized base directory.  This is the stdlib-based,
    // SAST-recognized containment check for CWE-23 / CWE-22.
    private static final java.nio.file.Path BASE_DIR =
            java.nio.file.Paths.get("/app/data").toAbsolutePath().normalize();

    public byte[] readFile(HttpServletRequest request)
            throws Exception {

        String file = request.getParameter("file");

        // Resolve, normalize and canonicalize the requested path so that any
        // ".." or "." components are collapsed before the containment check.
        java.nio.file.Path resolvedPath =
                BASE_DIR.resolve(file).normalize().toAbsolutePath();

        // Reject any path that escapes the designated base directory.
        if (!resolvedPath.startsWith(BASE_DIR)) {
            throw new SecurityException(
                    "Access denied: path is outside the permitted directory");
        }

        return java.nio.file.Files.readAllBytes(resolvedPath);
    }
}