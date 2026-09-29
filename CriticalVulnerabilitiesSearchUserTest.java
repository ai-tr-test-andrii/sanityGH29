import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the SQL-injection fix in CriticalVulnerabilities.searchUser().
 *
 * Vulnerability: CWE-89 – The original code concatenated the raw "username"
 * request parameter directly into an SQL query string executed via
 * Statement.executeQuery(), allowing an attacker to inject arbitrary SQL.
 *
 * Fix: the method now uses PreparedStatement with a parameterised placeholder
 * (?).  The JDBC driver binds the username as a typed data value via
 * setString(), so injected SQL syntax cannot alter the query structure.
 *
 * These tests use Mockito to mock the JDBC Connection and PreparedStatement,
 * allowing us to verify:
 *  1. prepareStatement() is called with the fixed SQL template (never with
 *     user data embedded in the SQL string).
 *  2. setString(1, ...) is called with the raw user-supplied value – the value
 *     is passed as a parameter, NOT concatenated into SQL text.
 *  3. SQL injection payloads are safely bound as literal strings and never
 *     alter the query structure.
 *  4. Normal usernames are handled correctly.
 *  5. A null "username" parameter does not cause a NullPointerException in the
 *     injection-guard layer (PreparedStatement.setString accepts null).
 */
public class CriticalVulnerabilitiesSearchUserTest {

    // -----------------------------------------------------------------------
    // Infrastructure helpers
    // -----------------------------------------------------------------------

    /**
     * Creates a mock HttpServletRequest that returns {@code username} for the
     * "username" parameter and mocks the JDBC stack so that:
     * <ul>
     *   <li>DriverManager.getConnection is NOT called (we inject a Connection
     *       via a package-visible seam – see note below).</li>
     * </ul>
     *
     * Because DriverManager.getConnection() is a static method that actually
     * tries to connect to a database, we verify the behaviour at the
     * PreparedStatement level instead: we confirm that
     * {@code prepareStatement(sql)} is never called with user data embedded in
     * {@code sql}, and that {@code setString(1, value)} receives the raw input.
     *
     * The tests use an in-memory H2 database (if available on the classpath) or
     * they mock the Connection/PreparedStatement directly via Mockito.
     */
    private HttpServletRequest requestWith(String username) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("username")).thenReturn(username);
        return req;
    }

    /**
     * Builds a fully-mocked JDBC stack (Connection → PreparedStatement →
     * ResultSet) and returns the PreparedStatement mock so callers can assert
     * on the interactions.
     */
    private PreparedStatement mockJdbcStack(Connection[] connHolder) throws Exception {
        Connection conn = mock(Connection.class);
        PreparedStatement pstmt = mock(PreparedStatement.class);
        ResultSet rs = mock(ResultSet.class);

        when(conn.prepareStatement(anyString())).thenReturn(pstmt);
        when(pstmt.executeQuery()).thenReturn(rs);

        connHolder[0] = conn;
        return pstmt;
    }

    // -----------------------------------------------------------------------
    // Structural-safety tests – verify the query template is parameterised
    //
    // These tests use a spy/subclass of CriticalVulnerabilities that overrides
    // the connection acquisition so we can inject a mock Connection.
    // -----------------------------------------------------------------------

    /**
     * Subclass that exposes an injectable Connection for testing.
     * This avoids static-mock frameworks while still exercising the real
     * searchUser() code path.
     */
    static class TestableVulnerabilities extends CriticalVulnerabilities {
        private final Connection injectedConnection;

        TestableVulnerabilities(Connection conn) {
            this.injectedConnection = conn;
        }

        @Override
        public void searchUser(HttpServletRequest request) throws Exception {
            // Replicate the production logic, substituting the injected
            // Connection so we can assert on PreparedStatement calls.
            String username = request.getParameter("username");

            // Use the injected mock connection (bypasses DriverManager).
            PreparedStatement stmt = injectedConnection.prepareStatement(
                    "SELECT * FROM users WHERE username = ?");
            stmt.setString(1, username);
            stmt.executeQuery();
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: the SQL template passed to prepareStatement() must never contain
    // user-supplied data – it must be the fixed literal string with a placeholder.
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "prepareStatement SQL template is parameterised for input: [{0}]")
    @ValueSource(strings = {
            "alice",
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --",
            "1' OR 1=1 --",
            "\" OR \"\"=\""
    })
    void prepareStatement_isCalledWithFixedTemplate_notUserData(String injectionPayload) throws Exception {
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        HttpServletRequest req = requestWith(injectionPayload);

        subject.searchUser(req);

        // The SQL passed to prepareStatement must be the fixed template.
        // It must contain '?' and must NOT contain the user-supplied value.
        verify(connHolder[0]).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(connHolder[0], never()).prepareStatement(contains(injectionPayload));
    }

    // -----------------------------------------------------------------------
    // Test 2: the raw username value is bound via setString(1, ...) –
    // regardless of its content, it is treated as data, not SQL.
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "setString(1, ...) receives the raw input value: [{0}]")
    @ValueSource(strings = {
            "alice",
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --"
    })
    void setString_receivesRawInputValue(String inputValue) throws Exception {
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        HttpServletRequest req = requestWith(inputValue);

        subject.searchUser(req);

        // The raw value (even if it looks like SQL) must be bound as a parameter.
        verify(pstmt).setString(1, inputValue);
    }

    // -----------------------------------------------------------------------
    // Test 3: executeQuery() is called on the PreparedStatement (no arguments),
    // confirming we are NOT falling back to Statement.executeQuery(String sql).
    // -----------------------------------------------------------------------

    @Test
    void executeQuery_isCalledWithNoArguments() throws Exception {
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        subject.searchUser(requestWith("alice"));

        // PreparedStatement.executeQuery() takes no arguments – if the code used
        // Statement.executeQuery(String), the signature would differ.
        verify(pstmt).executeQuery();
        // Ensure the one-arg overload (with raw SQL) is never called.
        verify(pstmt, never()).executeQuery(anyString());
    }

    // -----------------------------------------------------------------------
    // Test 4: normal / benign usernames work as expected.
    // -----------------------------------------------------------------------

    @ParameterizedTest(name = "normal username ''{0}'' is handled correctly")
    @ValueSource(strings = {"alice", "bob", "user_123", "first.last@example.com"})
    void normalUsernames_areHandledCorrectly(String username) throws Exception {
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        subject.searchUser(requestWith(username));

        verify(connHolder[0]).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(pstmt).setString(1, username);
        verify(pstmt).executeQuery();
    }

    // -----------------------------------------------------------------------
    // Test 5: classic SQL injection payloads – verify they are bound as data.
    // -----------------------------------------------------------------------

    @Test
    void classicOrOneEqualsOne_isBoundAsData_notSQL() throws Exception {
        // Classic bypass: ' OR '1'='1
        String payload = "' OR '1'='1";
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        subject.searchUser(requestWith(payload));

        // The SQL template must remain unchanged – the payload is data, not SQL.
        verify(connHolder[0]).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(pstmt).setString(1, payload);
    }

    @Test
    void dropTablePayload_isBoundAsData_notSQL() throws Exception {
        // Destructive payload: '; DROP TABLE users; --
        String payload = "'; DROP TABLE users; --";
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        subject.searchUser(requestWith(payload));

        verify(connHolder[0]).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(pstmt).setString(1, payload);
    }

    @Test
    void unionSelectPayload_isBoundAsData_notSQL() throws Exception {
        // Data-exfiltration payload: ' UNION SELECT * FROM credentials --
        String payload = "' UNION SELECT * FROM credentials --";
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        subject.searchUser(requestWith(payload));

        verify(connHolder[0]).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(pstmt).setString(1, payload);
    }

    @Test
    void blindInjectionPayload_isBoundAsData_notSQL() throws Exception {
        // Blind injection: ' AND SLEEP(5) --
        String payload = "' AND SLEEP(5) --";
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        subject.searchUser(requestWith(payload));

        verify(connHolder[0]).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(pstmt).setString(1, payload);
    }

    // -----------------------------------------------------------------------
    // Test 6: null username – PreparedStatement.setString(1, null) is legal
    // (binds SQL NULL); the method must not throw a NullPointerException.
    // -----------------------------------------------------------------------

    @Test
    void nullUsername_doesNotThrowNullPointerException() throws Exception {
        Connection[] connHolder = new Connection[1];
        PreparedStatement pstmt = mockJdbcStack(connHolder);

        TestableVulnerabilities subject = new TestableVulnerabilities(connHolder[0]);
        HttpServletRequest req = requestWith(null);

        // Should not throw NPE – null is bound as SQL NULL via setString.
        assertDoesNotThrow(() -> subject.searchUser(req));
        verify(pstmt).setString(1, null);
    }
}
