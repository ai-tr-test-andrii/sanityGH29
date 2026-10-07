import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

public class InfrastructureVulns {

    // Allowlist of hosts that the application is permitted to fetch from.
    // Only add trusted, external-facing hostnames here.
    private static final List<String> ALLOWED_HOSTS = Arrays.asList(
            "trusted-api.example.com",
            "cdn.example.com"
    );

    // 1. SSRF (High) — fixed by validating the host against an explicit allowlist
    // before making the outbound request.
    public String fetchUrl(HttpServletRequest request) throws Exception {

        String target =
                request.getParameter("url");

        // Parse with java.net.URI so that we can inspect the scheme and host
        // without risk of confusion attacks (e.g. embedded credentials).
        URI uri = new URI(target);

        String scheme = uri.getScheme();
        String host   = uri.getHost();

        // Enforce HTTPS-only and validate against the allowlist before fetching.
        if (!"https".equalsIgnoreCase(scheme) || host == null
                || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            throw new SecurityException(
                    "Request to disallowed URL was blocked: " + scheme + "://" + host);
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