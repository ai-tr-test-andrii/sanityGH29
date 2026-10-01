import javax.servlet.http.HttpServletRequest;
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

        String username = request.getParameter("username");

        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);

        // Use a PreparedStatement with a parameterized query to prevent SQL injection.
        // The username value is bound as a parameter via setString(), so it is treated
        // as data and never interpreted as SQL syntax by the database engine.
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, username);

        ResultSet rs = stmt.executeQuery();
    }
}
