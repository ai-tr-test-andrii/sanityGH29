import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class InfrastructureVulns {

    // Allowlist of trusted hosts the application is permitted to fetch from.
    // Add only hosts that the application legitimately needs to reach.
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "trusted.example.com",
            "api.example.com"
    ));

    // 1. SSRF (High) — fixed by parsing the URL with java.net.URI and
    //    validating the host against an explicit allowlist before opening
    //    the connection, preventing requests to arbitrary internal or
    //    external hosts.
    public String fetchUrl(HttpServletRequest request) throws Exception {

        String target =
                request.getParameter("url");

        // Parse and validate the URL using the stdlib URI parser.
        // URI.parseServerAuthority() rejects malformed authority components.
        URI uri = new URI(target).parseServerAuthority();

        String scheme = uri.getScheme();
        String host   = uri.getHost();

        // Only allow HTTPS (never file://, ftp://, gopher://, etc.)
        // and only allow requests to explicitly allowlisted hosts.
        if (!"https".equalsIgnoreCase(scheme)
                || host == null
                || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            throw new SecurityException(
                    "Request blocked: target URL is not on the allowlist.");
        }

        URL url = uri.toURL();

        return new String(
                url.openStream().readAllBytes());
    }

    // 2. XXE (High)
    public Document parseXml(InputStream xml)
            throws Exception {

        DocumentBuilderFactory factory =
                DocumentBuilderFactory.newInstance();

        DocumentBuilder builder =
                factory.newDocumentBuilder();

        return builder.parse(xml);
    }

    // 3. Weak Hash (Medium)
    public byte[] md5(String input)
            throws Exception {

        return MessageDigest
                .getInstance("MD5")
                .digest(input.getBytes());
    }

    // 4. Information Exposure (Medium)
    public void log(Exception e) {
        e.printStackTrace();
    }

    // 5. Open Redirect (Medium/High)
    public String redirect(
            HttpServletRequest request) {

        return request.getParameter(
                "redirectUrl");
    }
}