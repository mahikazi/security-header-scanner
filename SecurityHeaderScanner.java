import java.util.List;
import java.util.Scanner;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

public class SecurityHeaderScanner {

    static class SecurityCheck {
        String header;
        String name;
        String failMessage;
        String passMessage;

        SecurityCheck(String header, String name, String failMessage, String passMessage) {
            this.header = header;
            this.name = name;
            this.failMessage = failMessage;
            this.passMessage = passMessage;
        }
    }
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        List<SecurityCheck> checks = List.of(
            new SecurityCheck("strict-transport-security",
                "HSTS",
                "HSTS missing → site may allow insecure HTTP connections",
                "HSTS present"),

            new SecurityCheck("content-security-policy",
                "CSP",
                "CSP missing → vulnerable to XSS attacks",
                "CSP present"),

            new SecurityCheck("x-frame-options",
                "X-Frame-Options",
                "Missing → browser features not restricted",
                "Present"),

            new SecurityCheck("permissions-policy",
                "Permissions Policy",
                "Missing → browser features not restricted",
                "Present")
        );

        System.out.print("Enter the URL of a website to scan: ");
        String url = scanner.nextLine();

        scanWebsite(url, checks);

        scanner.close();

    }

    public static void scanWebsite(String url, List<SecurityCheck> checks) {

        if (!url.startsWith("http")) {
            url = "https://" + url;
        }

        try {
            URI.create(url);
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid url: " + url);
            return;
        }

        // Create HttpClient instance
        HttpClient client = HttpClient.newHttpClient();

        // Build HttpRequest with the target URI and GET method
        HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(url)).GET().build(); // Replace with target URI

        try {
            // Send the request synchronously and receive HttpResponse
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

            var headers = response.headers().map();

            System.out.println("\nScanning: " + url);
            System.out.println("\n--- Security Report ---\n");

            for (SecurityCheck check : checks) {
                if (!headers.containsKey(check.header)) {
                    System.out.println("[FAIL] " + check.name + " → " + check.failMessage);
                } else {
                    System.out.println("[PASS] " + check.name + " → " + check.passMessage);
                }
            }

            System.out.println("\nScan complete.");
        
            // Process the response
            // System.out.println("Status Code: " + response.statusCode());
            // System.out.println("Header: " + response.headers());
        
        } catch (Exception e) {
            System.out.println("Failed to analyze: " + url);
            System.out.println("Reason: The URL may be incorrect or unreachable.");
        }
    }
}
