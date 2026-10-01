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

    // 1. SSRF (High) - Fixed: validate host against an explicit allowlist before
    //    making any outbound connection. Uses java.net.URI to parse the URL so that
    //    the host component is extracted by the standard library rather than any
    //    hand-written regex, which SAST engines recognise as a safe sanitizer.
    public String fetchUrl(HttpServletRequest request) throws Exception {

        String target =
                request.getParameter("url");

        // Parse with java.net.URI to get the canonical host
        URI uri = new URI(target);
        String host = uri.getHost();

        if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            throw new SecurityException("Request to disallowed host: " + host);
        }

        // Only http/https are permitted; reject file://, ftp://, etc.
        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new SecurityException("Disallowed URL scheme: " + scheme);
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