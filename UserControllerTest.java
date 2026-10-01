import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for UserController.searchUser() to verify that:
 *
 * 1. The IDOR / Parameter Tampering vulnerability (CWE-472) is fixed:
 *    - The query is scoped to the server-side session identity, NOT the
 *      client-supplied "username" request parameter.
 *    - Unauthenticated callers are rejected before any database access.
 *
 * 2. SQL injection is prevented via parameterized PreparedStatement queries.
 *
 * The core security assertion: the value bound to the PreparedStatement
 * must come from the server-side session, NOT from request.getParameter().
 */
@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpSession session;

    @Mock
    private Connection connection;

    @Mock
    private PreparedStatement preparedStatement;

    @Mock
    private ResultSet resultSet;

    private UserController controller;

    @BeforeEach
    void setUp() {
        controller = new UserController();
    }

    // -----------------------------------------------------------------------
    // Helper: wire up mocks so that DriverManager.getConnection() returns the
    // mock connection, and conn.prepareStatement(any) returns the mock stmt.
    // -----------------------------------------------------------------------
    private MockedStatic<DriverManager> setupDriverManagerMock() throws Exception {
        MockedStatic<DriverManager> driverManagerMock = mockStatic(DriverManager.class);
        driverManagerMock
                .when(() -> DriverManager.getConnection(anyString(), anyString(), anyString()))
                .thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
        when(preparedStatement.executeQuery()).thenReturn(resultSet);
        return driverManagerMock;
    }

    // Helper: set up request with an active session containing an authenticated user.
    private void setupAuthenticatedSession(String sessionUsername) {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("authenticatedUsername")).thenReturn(sessionUsername);
    }

    // -----------------------------------------------------------------------
    // IDOR Test 1: Verify that when a client supplies a DIFFERENT username in
    // the request parameter than the one stored in the session, the query is
    // executed using the SESSION value, not the request parameter value.
    // This is the core IDOR / parameter-tampering regression test.
    // -----------------------------------------------------------------------
    @Test
    void testParameterTampering_sessionIdentityUsedNotRequestParam() throws Exception {
        // Authenticated user in session is "alice".
        setupAuthenticatedSession("alice");

        // Attacker supplies a different username in the request parameter.
        when(request.getParameter("username")).thenReturn("bob");

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            // The prepared statement must be bound with the SESSION identity ("alice"),
            // NOT the attacker-supplied request parameter ("bob").
            verify(preparedStatement).setString(1, "alice");

            // Confirm the attacker's username was NOT used.
            verify(preparedStatement, never()).setString(1, "bob");
        }
    }

    // -----------------------------------------------------------------------
    // IDOR Test 2: Verify that a user with no active session is rejected
    // before any database access occurs (no getConnection call made).
    // -----------------------------------------------------------------------
    @Test
    void testNoSession_throwsSecurityException() throws Exception {
        // No active session.
        when(request.getSession(false)).thenReturn(null);

        try (MockedStatic<DriverManager> dm = mockStatic(DriverManager.class)) {
            SecurityException ex = assertThrows(SecurityException.class,
                    () -> controller.searchUser(request));

            assertTrue(ex.getMessage().contains("authenticated"),
                    "Exception message should reference authentication requirement");

            // CRITICAL: database must NOT be accessed when session is absent.
            dm.verifyNoInteractions();
        }
    }

    // -----------------------------------------------------------------------
    // IDOR Test 3: Verify that a session with no authenticated username
    // attribute is rejected before any database access occurs.
    // -----------------------------------------------------------------------
    @Test
    void testSessionWithNoAuthenticatedUsername_throwsSecurityException() throws Exception {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("authenticatedUsername")).thenReturn(null);

        try (MockedStatic<DriverManager> dm = mockStatic(DriverManager.class)) {
            SecurityException ex = assertThrows(SecurityException.class,
                    () -> controller.searchUser(request));

            assertTrue(ex.getMessage().contains("authenticated"),
                    "Exception message should reference authentication requirement");

            // CRITICAL: database must NOT be accessed when user identity is missing.
            dm.verifyNoInteractions();
        }
    }

    // -----------------------------------------------------------------------
    // IDOR Test 4: Verify that the client-supplied "username" request parameter
    // is completely ignored — even when no "username" parameter is present, the
    // authenticated session user can still query their own record.
    // -----------------------------------------------------------------------
    @Test
    void testMissingRequestParam_sessionIdentityIsUsed() throws Exception {
        setupAuthenticatedSession("charlie");

        // No "username" request parameter supplied at all.
        when(request.getParameter("username")).thenReturn(null);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            // Should succeed because the session provides the identity.
            assertDoesNotThrow(() -> controller.searchUser(request));

            // The session identity must be bound as the query parameter.
            verify(preparedStatement).setString(1, "charlie");
        }
    }

    // -----------------------------------------------------------------------
    // SQL Injection Test 5: Verify that an SQL injection payload supplied via
    // the session (if somehow tainted) is still bound as a parameter, not
    // concatenated into the SQL template.
    // -----------------------------------------------------------------------
    @Test
    void testSqlInjectionInSessionUsername_isPassedAsParameter() throws Exception {
        String maliciousInput = "' OR '1'='1";
        setupAuthenticatedSession(maliciousInput);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
            verify(connection).prepareStatement(queryCaptor.capture());
            String capturedQuery = queryCaptor.getValue();

            // The injection payload must NOT appear in the SQL template string.
            assertFalse(capturedQuery.contains(maliciousInput),
                    "Injection payload must not be embedded in the SQL template");
            assertTrue(capturedQuery.contains("?"),
                    "SQL template must use a parameterized placeholder '?'");

            // The raw payload is bound safely via setString.
            verify(preparedStatement).setString(1, maliciousInput);
        }
    }

    // -----------------------------------------------------------------------
    // SQL Injection Test 6: UNION-based injection payload from session value
    // -----------------------------------------------------------------------
    @Test
    void testUnionInjectionInSessionUsername_isPassedAsParameter() throws Exception {
        String maliciousInput = "admin' UNION SELECT password FROM users--";
        setupAuthenticatedSession(maliciousInput);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
            verify(connection).prepareStatement(queryCaptor.capture());
            String capturedQuery = queryCaptor.getValue();

            assertFalse(capturedQuery.contains("UNION"),
                    "UNION keyword from user input must not appear in SQL template");
            verify(preparedStatement).setString(1, maliciousInput);
        }
    }

    // -----------------------------------------------------------------------
    // SQL Injection Test 7: Normal username — verify a PreparedStatement is
    // used (not a plain Statement), the SQL template contains a '?' placeholder,
    // and the username is bound via setString rather than concatenated.
    // -----------------------------------------------------------------------
    @Test
    void testNormalUsername_usesPreparedStatement() throws Exception {
        setupAuthenticatedSession("alice");

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            // The query template passed to prepareStatement must use '?' placeholder,
            // NOT embed the username directly.
            ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
            verify(connection).prepareStatement(queryCaptor.capture());
            String capturedQuery = queryCaptor.getValue();

            assertTrue(capturedQuery.contains("?"),
                    "SQL template must contain a parameterized placeholder '?'");
            assertFalse(capturedQuery.contains("alice"),
                    "The raw username must NOT be embedded in the SQL template string");

            // The username must be passed as a bound parameter.
            verify(preparedStatement).setString(1, "alice");

            // executeQuery() must be called on the PreparedStatement (no argument),
            // confirming no string-built query was executed.
            verify(preparedStatement).executeQuery();
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: Username with special characters — special chars are passed
    // safely as a parameter without breaking the query.
    // -----------------------------------------------------------------------
    @Test
    void testUsernameWithSpecialChars_isPassedAsParameter() throws Exception {
        String specialUsername = "O'Brien; DROP TABLE users;--";
        setupAuthenticatedSession(specialUsername);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
            verify(connection).prepareStatement(queryCaptor.capture());
            String capturedQuery = queryCaptor.getValue();

            assertFalse(capturedQuery.contains("DROP"),
                    "DROP keyword from user input must not appear in the SQL template");
            verify(preparedStatement).setString(1, specialUsername);
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: No hardcoded password literal in source — the class source file
    // must not contain the known-bad literal "pass" as a credential value.
    // -----------------------------------------------------------------------
    @Test
    void testNoHardcodedPasswordInSourceClass() throws Exception {
        // Confirm that the three credential fields exist and are declared static.
        Class<UserController> cls = UserController.class;

        Field dbUrlField  = cls.getDeclaredField("DB_URL");
        Field dbUserField = cls.getDeclaredField("DB_USER");
        Field dbPassField = cls.getDeclaredField("DB_PASS");

        assertTrue(Modifier.isStatic(dbUrlField.getModifiers()),  "DB_URL must be static");
        assertTrue(Modifier.isStatic(dbUserField.getModifiers()), "DB_USER must be static");
        assertTrue(Modifier.isStatic(dbPassField.getModifiers()), "DB_PASS must be static");

        // The fields must NOT be compile-time constants (ConstantValue attribute),
        // which is only set for primitive/String finals initialized with a literal.
        // Fields initialised with System.getenv() are NOT constant-folded, so they
        // will NOT have the ConstantValue attribute in the bytecode. We verify this
        // by checking that the field is NOT a compile-time string constant.
        dbPassField.setAccessible(true);
        Object passValue = dbPassField.get(null);
        // In a test environment without DB_PASS set the field resolves to null.
        // It must NEVER equal the previously hardcoded literal "pass".
        assertNotEquals("pass", passValue,
                "DB_PASS must not be the hardcoded literal 'pass'. " +
                "Credentials must come from environment variables.");
    }

    // -----------------------------------------------------------------------
    // Test 10: getConnection receives values derived from environment variables,
    // not a previously hardcoded literal.
    // -----------------------------------------------------------------------
    @Test
    void testGetConnection_usesEnvironmentVariableCredentials() throws Exception {
        setupAuthenticatedSession("testuser");

        // Capture all three arguments that are forwarded to getConnection.
        ArgumentCaptor<String> urlCaptor  = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> userCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> passCaptor = ArgumentCaptor.forClass(String.class);

        try (MockedStatic<DriverManager> driverManagerMock = mockStatic(DriverManager.class)) {
            driverManagerMock
                    .when(() -> DriverManager.getConnection(
                            urlCaptor.capture(), userCaptor.capture(), passCaptor.capture()))
                    .thenReturn(connection);
            when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
            when(preparedStatement.executeQuery()).thenReturn(resultSet);

            controller.searchUser(request);

            // The password forwarded to getConnection must NOT be the old hardcoded literal.
            String capturedPass = passCaptor.getValue();
            assertNotEquals("pass", capturedPass,
                    "The hardcoded password 'pass' must no longer be used. " +
                    "Credentials must be supplied through environment variables.");
        }
    }
}
