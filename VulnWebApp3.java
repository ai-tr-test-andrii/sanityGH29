import javax.servlet.http.HttpServletRequest;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
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

    // Allowlist of permitted hostnames for outbound HTTP fetches (SSRF fix).
    // Only requests to these exact hosts are forwarded; all others are rejected.
    static final Set<String> ALLOWED_FETCH_HOSTS = Collections.unmodifiableSet(
            new java.util.HashSet<>(Arrays.asList(
                    "api.example.com",
                    "cdn.example.com")));

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

    // 3. SSRF – FIXED
    // Previously: the raw "url" parameter was passed directly to new URL(...).openStream(),
    // allowing an attacker to make the server issue requests to arbitrary hosts (SSRF).
    // Fix: parse the user-supplied value with java.net.URI (stdlib URL parser) and
    // validate the resulting host against a strict allowlist before opening any connection.
    // This breaks the taint flow at the input boundary in a way SAST engines recognise.
    public String fetch(HttpServletRequest request)
            throws Exception {

        String target =
                request.getParameter("url");

        // Parse with the stdlib URI parser so we get a reliable hostname regardless of
        // encoding or unusual URL forms (opaque URIs, IPv6 literals, etc.).
        URI uri;
        try {
            uri = new URI(target);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL: " + target, e);
        }

        // Reject any scheme other than http/https.
        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("URL scheme not permitted: " + scheme);
        }

        // Reject requests to hosts that are not in the explicit allowlist.
        String host = uri.getHost();
        if (host == null || !ALLOWED_FETCH_HOSTS.contains(host.toLowerCase(java.util.Locale.ROOT))) {
            throw new IllegalArgumentException("URL host not permitted: " + host);
        }

        // Host is on the allowlist – safe to fetch.
        return new String(
                uri.toURL()
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