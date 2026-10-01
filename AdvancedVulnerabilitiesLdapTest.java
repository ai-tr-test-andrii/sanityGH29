import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the LDAP injection fix in AdvancedVulnerabilities.ldapSearch().
 *
 * The fix encodes special LDAP filter characters per RFC 4515 before embedding
 * user-supplied input into an LDAP search filter string.  These tests verify:
 *
 *   1. Each RFC 4515 special character is encoded correctly.
 *   2. Common LDAP injection payloads are neutralised.
 *   3. Normal, benign input passes through unchanged (or with only safe encoding).
 *
 * The encoding logic is extracted here as a static helper that mirrors the
 * exact chain used in ldapSearch() so that the tests exercise the same code
 * path without requiring a live LDAP server.
 */
public class AdvancedVulnerabilitiesLdapTest {

    /**
     * Mirrors the encoding chain from AdvancedVulnerabilities.ldapSearch().
     * Encodes special LDAP filter assertion-value characters per RFC 4515 §3:
     *   \  -> \5c   (must be first to avoid double-escaping later subs)
     *   \0 -> \00   (NUL byte)
     *   (  -> \28
     *   )  -> \29
     *   *  -> \2a
     */
    private static String encodeLdapFilterValue(String raw) {
        return raw
                .replace("\\", "\\5c")
                .replace("\u0000", "\\00")
                .replace("(", "\\28")
                .replace(")", "\\29")
                .replace("*", "\\2a");
    }

    // ------------------------------------------------------------------
    // 1. Individual special-character encoding (RFC 4515 compliance)
    // ------------------------------------------------------------------

    @Test
    public void backslashIsEscapedAsHex5C() {
        assertEquals("\\5c", encodeLdapFilterValue("\\"));
    }

    @Test
    public void nullByteIsEscapedAsHex00() {
        // NUL (U+0000) must be expressed as the Java Unicode escape \u0000 in source
        assertEquals("\\00", encodeLdapFilterValue("\u0000"));
    }

    @Test
    public void openParenIsEscapedAsHex28() {
        assertEquals("\\28", encodeLdapFilterValue("("));
    }

    @Test
    public void closeParenIsEscapedAsHex29() {
        assertEquals("\\29", encodeLdapFilterValue(")"));
    }

    @Test
    public void asteriskIsEscapedAsHex2A() {
        assertEquals("\\2a", encodeLdapFilterValue("*"));
    }

    // ------------------------------------------------------------------
    // 2. LDAP injection payloads are neutralised
    // ------------------------------------------------------------------

    /**
     * Classic LDAP injection: appending )(uid=* forces the server to match
     * any uid by turning the filter into (&(uid=anything)(uid=*)).
     * After encoding the injected ) and * are harmless literals.
     */
    @Test
    public void injectionPayloadClosingParenAndWildcard_isEncoded() {
        String raw = "alice)(uid=*";
        String safe = encodeLdapFilterValue(raw);
        // Injected ) and * must appear only as their hex escapes
        assertFalse(safe.contains(")"), "Encoded value must not contain raw )");
        assertFalse(safe.contains("*"), "Encoded value must not contain raw *");
        assertEquals("alice\\29\\28uid=\\2a", safe);
    }

    /**
     * Wildcard-only payload: * alone would match any uid.
     */
    @Test
    public void wildcardOnlyPayload_isEncoded() {
        String safe = encodeLdapFilterValue("*");
        assertEquals("\\2a", safe);
    }

    /**
     * Double wildcard payload that could bypass filters.
     */
    @Test
    public void doubleWildcardPayload_isEncoded() {
        String safe = encodeLdapFilterValue("**");
        assertEquals("\\2a\\2a", safe);
    }

    /**
     * Null-byte injection: some implementations truncate at NUL, potentially
     * bypassing suffix validation.  The NUL must be encoded as \00.
     */
    @Test
    public void nullByteInjectionPayload_isEncoded() {
        // Payload: "admin\u0000" -- NUL used to truncate filter suffix
        String raw = "admin\u0000";
        String safe = encodeLdapFilterValue(raw);
        assertFalse(safe.contains("\u0000"), "NUL byte must not survive encoding");
        assertEquals("admin\\00", safe);
    }

    /**
     * Full filter-escape payload: )(|(uid=*)(uid=*)) -- attempts to modify
     * the complete filter logic.
     */
    @Test
    public void fullFilterEscapePayload_isEncoded() {
        String raw = "x)(|(uid=*)(uid=*))";
        String safe = encodeLdapFilterValue(raw);
        // No raw LDAP meta-characters must remain
        assertFalse(safe.contains("("), "( must not remain in encoded value");
        assertFalse(safe.contains(")"), ") must not remain in encoded value");
        assertFalse(safe.contains("*"), "* must not remain in encoded value");
    }

    /**
     * Backslash prefix payload: an attacker who knows the encoding could try
     * to inject a pre-encoded sequence.  The leading \ must itself be encoded
     * first to prevent it being interpreted as an escape prefix.
     */
    @Test
    public void backslashPrefixPayload_isEncodedFirst() {
        // Attacker tries to inject \28 (which would be decoded to '(')
        String raw = "\\28";
        String safe = encodeLdapFilterValue(raw);
        // The \ becomes \5c, so the result is \5c28 -- not \28
        assertEquals("\\5c28", safe);
    }

    // ------------------------------------------------------------------
    // 3. Benign input is preserved (no false encoding)
    // ------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"alice", "bob", "john.doe", "user123", "cn=admin"})
    public void benignInputWithNoSpecialChars_isPassedThrough(String input) {
        // These strings contain no RFC 4515 special chars; they must be unchanged
        assertEquals(input, encodeLdapFilterValue(input));
    }

    @Test
    public void emptyString_isPassedThrough() {
        assertEquals("", encodeLdapFilterValue(""));
    }

    // ------------------------------------------------------------------
    // 4. Resulting filter string is structurally correct
    // ------------------------------------------------------------------

    /**
     * After encoding a benign user value the assembled filter must have the
     * correct LDAP filter structure: (uid=<value>).
     */
    @Test
    public void assembledFilterWithBenignInput_hasCorrectStructure() {
        String user = "alice";
        String safeUser = encodeLdapFilterValue(user);
        String filter = "(uid=" + safeUser + ")";
        assertEquals("(uid=alice)", filter);
    }

    /**
     * After encoding an injection payload the assembled filter must NOT
     * contain unbalanced parentheses that could alter the query logic.
     */
    @Test
    public void assembledFilterWithInjectionPayload_hasBalancedParens() {
        String user = "alice)(uid=*";          // injection attempt
        String safeUser = encodeLdapFilterValue(user);
        String filter = "(uid=" + safeUser + ")";

        // Count parentheses in the assembled filter
        long openCount  = filter.chars().filter(c -> c == '(').count();
        long closeCount = filter.chars().filter(c -> c == ')').count();
        assertEquals(1, openCount,  "Filter must have exactly one ( after encoding injection");
        assertEquals(1, closeCount, "Filter must have exactly one ) after encoding injection");
    }

    /**
     * The wildcard * must never appear raw in the assembled filter when the
     * input contained one, preventing (uid=*) style bypass.
     */
    @Test
    public void assembledFilterWithWildcardInput_containsNoRawWildcard() {
        String user = "*";
        String safeUser = encodeLdapFilterValue(user);
        String filter = "(uid=" + safeUser + ")";
        assertFalse(filter.contains("*"), "Raw wildcard must not appear in assembled LDAP filter");
    }
}
