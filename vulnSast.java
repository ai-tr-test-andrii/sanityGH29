import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
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
import java.util.Hashtable;

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

    // 2. Command Injection (High)
    public void executeCommand(HttpServletRequest request)
            throws Exception {

        String cmd = request.getParameter("cmd");

        Runtime.getRuntime().exec(cmd);
    }

    // 3. LDAP Injection (High) - Fixed: encode special LDAP filter characters per RFC 4515
    public void ldapSearch(HttpServletRequest request)
            throws Exception {

        String user = request.getParameter("user");

        // Encode special LDAP filter characters to prevent LDAP injection (RFC 4515).
        // The characters that must be escaped in a filter assertion value are:
        //   \ (backslash)  -- escaped first to avoid double-escaping later replacements
        //    (NUL)   -- escaped as \00
        //   ( ) *          -- the other reserved LDAP filter meta-characters
        String safeUser = user
                .replace("\\", "\\5c")
                .replace("\u0000", "\\00")
                .replace("(", "\\28")
                .replace(")", "\\29")
                .replace("*", "\\2a");

        Hashtable<String, String> env = new Hashtable<>();

        DirContext ctx = new InitialDirContext(env);

        ctx.search(
                "dc=test,dc=com",
                "(uid=" + safeUser + ")",
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
