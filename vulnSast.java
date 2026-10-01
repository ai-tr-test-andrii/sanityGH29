import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

public class AdvancedVulnerabilities {

    // 1. SQL Injection (High)
    public void findUser(HttpServletRequest request) throws Exception {

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

    // Allowlist of permitted commands — only these exact tokens may be executed.
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(
            Arrays.asList("ls", "pwd", "date", "whoami"));

    // 2. Command Injection (High) — FIXED: use allowlist + ProcessBuilder argv list.
    // The user-supplied "cmd" value is validated against a strict allowlist before
    // use, and the command is passed as a String[] to ProcessBuilder so the OS
    // kernel never interprets it through a shell. This breaks the taint flow
    // recognised by CWE-77/CWE-78 scanners.
    public void executeCommand(HttpServletRequest request)
            throws Exception {

        String cmd = request.getParameter("cmd");

        // Reject any value that is not on the explicit allowlist.
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd)) {
            throw new IllegalArgumentException("Command not permitted: " + cmd);
        }

        // Pass the pre-validated command as a single-element argv array.
        // ProcessBuilder(String[]) does NOT invoke a shell, so shell
        // metacharacters such as ; | & ` $() cannot be injected.
        new ProcessBuilder(cmd).start();
    }

    // 3. LDAP Injection (High)
    public void ldapSearch(HttpServletRequest request)
            throws Exception {

        String user = request.getParameter("user");

        Hashtable<String, String> env = new Hashtable<>();

        DirContext ctx = new InitialDirContext(env);

        ctx.search(
                "dc=test,dc=com",
                "(uid=" + user + ")",
                null);
    }

    // 4. XPath Injection (High)
    public String findNode(HttpServletRequest request)
            throws Exception {

        String id = request.getParameter("id");

        XPath xpath = XPathFactory.newInstance().newXPath();

        return xpath.evaluate(
                "//users/user[@id='" + id + "']",
                new org.xml.sax.InputSource()
        );
    }

    // 5. Insecure Deserialization (High)
    public Object deserialize()
            throws Exception {

        ObjectInputStream in =
                new ObjectInputStream(
                        new FileInputStream("object.bin"));

        return in.readObject();
    }

    // 6. Path Traversal (High)
    public byte[] readFile(HttpServletRequest request)
            throws Exception {

        String file = request.getParameter("file");

        return Files.readAllBytes(
                Paths.get("/tmp/" + file));
    }
}