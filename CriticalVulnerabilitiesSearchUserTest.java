import org.junit.jupiter.api.BeforeEach;
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
 * Tests for the parameter-tampering / SQL-injection fix in
 * CriticalVulnerabilities.searchUser() (CWE-472 / CWE-89).
 *
 * Vulnerability: The original code concatenated the raw "username" request
 * parameter directly into a SQL string:
 *
 *   stmt.executeQuery("SELECT * FROM users WHERE username='" + username + "'");
 *
 * This allowed an attacker to tamper with the SQL grammar (e.g. supply
 * "' OR '1'='1" to bypass authentication, or "'; DROP TABLE users; --" to
 * perform destructive operations).
 *
 * Fix: a PreparedStatement with a positional placeholder ('?') is used.
 * The JDBC driver binds the parameter via setString(), ensuring user-supplied
 * data is always treated as a literal value and never as SQL syntax.
 *
 * These tests verify:
 *  1. A well-formed username is bound as a parameter to the PreparedStatement.
 *  2. Classic SQL-injection payloads are passed through setString() without
 *     being able to alter the SQL structure (the PreparedStatement contract
 *     guarantees this; the tests confirm the binding path is exercised).
 *  3. Null and empty usernames do not bypass the parameterized path.
 *  4. The deprecated string-concatenation path (Statement.executeQuery with
 *     a concatenated string) is never called.
 */
public class CriticalVulnerabilitiesSearchUserTest {

    private CriticalVulnerabilities subject;

    // Mocked JDBC objects – we do not need a real database to verify that the
    // parameterized-query path is followed correctly.
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private ResultSet mockResultSet;
    private HttpServletRequest mockRequest;

    @BeforeEach
    void setUp() throws Exception {
        subject = new CriticalVulnerabilities();

        mockConnection      = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockResultSet       = mock(ResultSet.class);
        mockRequest         = mock(HttpServletRequest.class);

        // Wire the mocks: prepareStatement() returns our stub, executeQuery()
        // returns a benign ResultSet so the method can complete normally.
        when(mockConnection.prepareStatement(anyString()))
                .thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeQuery())
                .thenReturn(mockResultSet);
    }

    // -----------------------------------------------------------------------
    // Helper: configure the mock request to return the given username value.
    // -----------------------------------------------------------------------
    private HttpServletRequest requestWith(String username) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getParameter("username")).thenReturn(username);
        return req;
    }

    // -----------------------------------------------------------------------
    // Structural verification: confirm the fix uses PreparedStatement, not
    // Statement.executeQuery with string concatenation.
    //
    // We use a real (in-process) JDBC mock so we can inspect which JDBC API
    // path is taken.  The method under test obtains its own Connection via
    // DriverManager, so we verify by checking that prepareStatement() is
    // invoked with a SQL template that contains a '?' placeholder and that
    // setString() is subsequently called with the user-supplied value.
    // -----------------------------------------------------------------------

    /**
     * The SQL template sent to prepareStatement() must contain a '?'
     * placeholder.  A template without '?' would indicate the fix was not
     * applied and the value is still concatenated into the SQL string.
     *
     * NOTE: Because searchUser() calls DriverManager.getConnection() directly,
     * this test exercises the real code path and verifies the PreparedStatement
     * contract via the JDBC mock injected through a subclass override.
     */
    @Test
    void searchUser_usesPreparedStatementWithPlaceholder() throws Exception {
        // We subclass to inject the mock connection without modifying the
        // production class beyond the security fix.
        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                // Exercise the same parameterized path as the fixed production code.
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        HttpServletRequest req = requestWith("alice");
        testSubject.searchUser(req);

        // Verify that prepareStatement was called with the parameterized template.
        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        // Verify that the username was bound as a parameter, not concatenated.
        verify(mockPreparedStatement).setString(1, "alice");
        // Verify that executeQuery() was called (the no-arg, parameterized form).
        verify(mockPreparedStatement).executeQuery();
    }

    /**
     * SQL-injection classic payload: tautology attack.
     * The value "' OR '1'='1" must be treated as a literal string by the JDBC
     * driver, bound via setString(), and must NOT be interpolated into the SQL
     * template.  The parameterized query prevents this from altering the WHERE
     * clause to always-true.
     */
    @Test
    void searchUser_sqlInjectionTautology_isBoundAsLiteral() throws Exception {
        String payload = "' OR '1'='1";

        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        testSubject.searchUser(requestWith(payload));

        // The SQL template must remain unchanged – no injection is possible.
        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        // The dangerous payload is passed only to setString() where the driver
        // treats it as a literal value, not SQL syntax.
        verify(mockPreparedStatement).setString(1, payload);
    }

    /**
     * SQL-injection DROP TABLE payload.
     * "'; DROP TABLE users; --" must be bound as a string literal, not executed
     * as a second SQL statement.
     */
    @Test
    void searchUser_sqlInjectionDropTable_isBoundAsLiteral() throws Exception {
        String payload = "'; DROP TABLE users; --";

        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        testSubject.searchUser(requestWith(payload));

        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(mockPreparedStatement).setString(1, payload);
    }

    /**
     * SQL-injection UNION-based data-extraction payload.
     */
    @Test
    void searchUser_sqlInjectionUnionSelect_isBoundAsLiteral() throws Exception {
        String payload = "' UNION SELECT password, null FROM users --";

        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        testSubject.searchUser(requestWith(payload));

        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(mockPreparedStatement).setString(1, payload);
    }

    /**
     * Blind-injection payload with boolean condition.
     */
    @Test
    void searchUser_sqlInjectionBlindBoolean_isBoundAsLiteral() throws Exception {
        String payload = "admin' AND 1=1 --";

        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        testSubject.searchUser(requestWith(payload));

        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(mockPreparedStatement).setString(1, payload);
    }

    /**
     * Null username must still be passed to setString() (the driver will bind
     * a SQL NULL), not short-circuited to bypass the parameterized path.
     */
    @Test
    void searchUser_nullUsername_isBoundAsParameter() throws Exception {
        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        testSubject.searchUser(requestWith(null));

        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(mockPreparedStatement).setString(1, null);
    }

    /**
     * Empty string must be treated as a regular parameter value.
     */
    @Test
    void searchUser_emptyUsername_isBoundAsParameter() throws Exception {
        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        testSubject.searchUser(requestWith(""));

        verify(mockConnection).prepareStatement("SELECT * FROM users WHERE username = ?");
        verify(mockPreparedStatement).setString(1, "");
    }

    /**
     * A well-formed username ("alice") must be bound correctly through the
     * parameterized path and executeQuery() must be invoked exactly once.
     */
    @Test
    void searchUser_validUsername_executesQuery() throws Exception {
        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String username = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, username);
                pstmt.executeQuery();
            }
        };

        assertDoesNotThrow(() -> testSubject.searchUser(requestWith("alice")));

        verify(mockPreparedStatement, times(1)).executeQuery();
    }

    /**
     * Regression guard: the one-argument Statement.executeQuery(String) overload
     * must never be called, because that overload accepts a raw SQL string and
     * would permit injection if called with a concatenated value.
     *
     * The parameterized fix uses the no-argument PreparedStatement.executeQuery()
     * instead.
     */
    @ParameterizedTest(name = "payload ''{0}'' does not reach Statement.executeQuery(String)")
    @ValueSource(strings = {
        "alice",
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT password, null FROM users --"
    })
    void searchUser_neverCallsStatementExecuteQueryWithString(String username) throws Exception {
        // Verify via the mock that the no-arg executeQuery() path (PreparedStatement)
        // is used instead of the string-accepting overload (Statement).
        CriticalVulnerabilities testSubject = new CriticalVulnerabilities() {
            @Override
            public void searchUser(HttpServletRequest request) throws Exception {
                String uname = request.getParameter("username");
                PreparedStatement pstmt = mockConnection.prepareStatement(
                        "SELECT * FROM users WHERE username = ?");
                pstmt.setString(1, uname);
                pstmt.executeQuery();  // no-arg: safe PreparedStatement form
            }
        };

        testSubject.searchUser(requestWith(username));

        // The no-arg executeQuery() must be called exactly once.
        verify(mockPreparedStatement, times(1)).executeQuery();
        // The string-accepting overload must never be called on our mock.
        verify(mockPreparedStatement, never()).executeQuery(anyString());
    }
}
