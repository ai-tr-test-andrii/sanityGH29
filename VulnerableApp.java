import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserController {

    public void searchUser(HttpServletRequest request) throws Exception {

        String username = request.getParameter("username");

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/test",
                "user",
                "pass");

        // Use a PreparedStatement with a parameterized query to prevent SQL injection.
        // The username value is bound as a parameter via setString(), so it is treated
        // as data and never interpreted as SQL syntax by the database engine.
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, username);

        ResultSet rs = stmt.executeQuery();
    }
}
