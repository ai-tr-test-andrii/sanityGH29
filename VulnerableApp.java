import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserController {

    // Database credentials are read from environment variables at runtime so
    // that no sensitive values are ever embedded in source code or binaries.
    private static final String DB_URL  = System.getenv("DB_URL");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASS = System.getenv("DB_PASS");

    public void searchUser(HttpServletRequest request) throws Exception {

        // Retrieve the authenticated user's identity from the server-side session.
        // The session is managed server-side and cannot be tampered with by the client,
        // so this is a trusted source of the current user's identity (CWE-472 mitigation).
        HttpSession session = request.getSession(false);
        if (session == null) {
            throw new SecurityException("No active session found. User must be authenticated.");
        }

        String authenticatedUsername = (String) session.getAttribute("authenticatedUsername");
        if (authenticatedUsername == null) {
            throw new SecurityException("User is not authenticated.");
        }

        // Ignore the client-supplied "username" parameter entirely for access control.
        // Instead, use the server-side session identity to restrict the query so that
        // users can only retrieve their own record. This eliminates the IDOR/parameter-
        // tampering risk: even if a client supplies a different username in the request,
        // the query is always scoped to the session-authenticated user.
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);

        // Use a PreparedStatement with a parameterized query to prevent SQL injection.
        // The authenticatedUsername value is bound as a parameter via setString(), so it
        // is treated as data and never interpreted as SQL syntax by the database engine.
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, authenticatedUsername);

        ResultSet rs = stmt.executeQuery();
    }
}
