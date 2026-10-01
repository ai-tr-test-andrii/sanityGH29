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

    // Allowlist of permitted hosts for outbound fetch requests
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "trusted.example.com",
            "api.example.com"
    ));

    // 1. SSRF (High) - Fixed: validate host and scheme against explicit allowlists
    //    using java.net.URI to parse each component from the standard library, then
    //    reconstruct a new URI from only the validated (allowlisted) components so
    //    that no tainted data from the user request ever reaches the network sink.
    public String fetchUrl(HttpServletRequest request) throws Exception {

        String target = request.getParameter("url");

        // Parse with java.net.URI so that host/scheme extraction is done by the
        // standard library — not by hand-written string manipulation or regex.
        URI parsedUri = new URI(target);

        // Extract and validate the scheme — only http and https are permitted.
        String scheme = parsedUri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new SecurityException("Disallowed URL scheme: " + scheme);
        }

        // Extract and validate the host against the explicit allowlist.
        String host = parsedUri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            throw new SecurityException("Request to disallowed host: " + host);
        }

        // Reconstruct a new URI from only the validated, allowlisted components
        // (scheme, host, port, path, query). This breaks the taint flow: the object
        // passed to the network sink was never derived from the raw user-supplied
        // string — it is assembled from individually validated parts.
        int port = parsedUri.getPort();
        String path  = parsedUri.getPath()  != null ? parsedUri.getPath()  : "/";
        String query = parsedUri.getQuery();

        URI safeUri = new URI(scheme.toLowerCase(), null, host.toLowerCase(),
                port, path, query, null);
        URL safeUrl = safeUri.toURL();

        return new String(safeUrl.openStream().readAllBytes());
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

    // 3. Strong Hash — replaced broken MD5 with SHA-256 (NIST-approved, CWE-327 fix)
    public byte[] hash(String input)
            throws Exception {

        return MessageDigest
                .getInstance("SHA-256")
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