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