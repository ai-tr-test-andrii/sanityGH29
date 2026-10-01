import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for UserController.searchUser() to verify that SQL injection
 * has been remediated via parameterized PreparedStatement queries.
 *
 * The core security assertion in every test is: the user-supplied username
 * value must reach the database ONLY as a bound parameter (via setString),
 * never as literal SQL text embedded in the query string.
 */
@ExtendWith(MockitoExtension.class)
public class UserControllerTest {

    @Mock
    private HttpServletRequest request;

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

    // -----------------------------------------------------------------------
    // Test 1: Normal username — verify a PreparedStatement is used (not a
    // plain Statement), that the SQL template contains a '?' placeholder, and
    // that the username is bound via setString rather than concatenated.
    // -----------------------------------------------------------------------
    @Test
    void testNormalUsername_usesPreparedStatement() throws Exception {
        when(request.getParameter("username")).thenReturn("alice");

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
    // Test 2: Classic SQL injection payload — verify the payload is treated as
    // a literal string parameter and is NEVER embedded in the SQL template.
    // -----------------------------------------------------------------------
    @Test
    void testSqlInjectionPayload_isPassedAsParameter() throws Exception {
        String maliciousInput = "' OR '1'='1";
        when(request.getParameter("username")).thenReturn(maliciousInput);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
            verify(connection).prepareStatement(queryCaptor.capture());
            String capturedQuery = queryCaptor.getValue();

            // The injection payload must NOT appear in the SQL template string.
            assertFalse(capturedQuery.contains(maliciousInput),
                    "Injection payload must not be embedded in the SQL template");
            assertTrue(capturedQuery.contains("?"),
                    "SQL template must use a parameterized placeholder");

            // The raw payload must be bound safely via setString.
            verify(preparedStatement).setString(1, maliciousInput);
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: UNION-based injection payload
    // -----------------------------------------------------------------------
    @Test
    void testUnionInjectionPayload_isPassedAsParameter() throws Exception {
        String maliciousInput = "admin' UNION SELECT password FROM users--";
        when(request.getParameter("username")).thenReturn(maliciousInput);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            controller.searchUser(request);

            ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
            verify(connection).prepareStatement(queryCaptor.capture());
            String capturedQuery = queryCaptor.getValue();

            assertFalse(capturedQuery.contains("UNION"),
                    "UNION keyword from user input must not appear in SQL template");
            assertFalse(capturedQuery.contains(maliciousInput),
                    "Injection payload must not be embedded in the SQL template");
            verify(preparedStatement).setString(1, maliciousInput);
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: Blank username — verify the system handles it without error.
    // -----------------------------------------------------------------------
    @Test
    void testBlankUsername_doesNotThrow() throws Exception {
        when(request.getParameter("username")).thenReturn("");

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            assertDoesNotThrow(() -> controller.searchUser(request));
            verify(preparedStatement).setString(1, "");
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: Null username — verify the system handles null gracefully.
    // -----------------------------------------------------------------------
    @Test
    void testNullUsername_doesNotThrow() throws Exception {
        when(request.getParameter("username")).thenReturn(null);

        try (MockedStatic<DriverManager> dm = setupDriverManagerMock()) {
            assertDoesNotThrow(() -> controller.searchUser(request));
            verify(preparedStatement).setString(1, null);
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: Username with special characters — special chars are passed
    // safely as a parameter without breaking the query.
    // -----------------------------------------------------------------------
    @Test
    void testUsernameWithSpecialChars_isPassedAsParameter() throws Exception {
        String specialUsername = "O'Brien; DROP TABLE users;--";
        when(request.getParameter("username")).thenReturn(specialUsername);

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
}
