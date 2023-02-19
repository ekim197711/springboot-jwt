package com.example.springbootjwt.security;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

class JwtHelperTest {
    final static String privateKey = System.getenv("PRIVATE_KEY_FOR_DEMO");

    private String idToken() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException {
        String email = "weather-client-application@mikes-demo.iam.gserviceaccount.com";
        String urlString = "https://weather-xdqrgy4k7a-lm.a.run.app";
        String tokenUrl = "https://www.googleapis.com/oauth2/v4/token";
        String audience = "https://www.googleapis.com/oauth2/v4/token";
        String targetAudience = urlString;
        String jwt = new JwtHelper().generateJWT(
                email, email, audience, targetAudience, privateKey
        );
        System.out.println(jwt);

        RestTemplate rt = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
        headers.set(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");
        String body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwt;
        RequestEntity<String> request = new RequestEntity<>(body,
                headers, HttpMethod.POST, new URI(tokenUrl));
        ResponseEntity<HashMap> response = rt.exchange(request, HashMap.class);
        Assertions.assertEquals(200, response.getStatusCode().value());
        System.out.println(response.getHeaders());
        System.out.println(response.getBody());

        String idToken = response.getBody().get("id_token").toString();
        return idToken;
    }

    @Test
    void sendRequestToCloudFunction() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException {
        String idToken = idToken();
        String urlString = "https://weather-xdqrgy4k7a-lm.a.run.app";

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + idToken);
        RequestEntity<String> functionRequest = new RequestEntity<>("",
                headers, HttpMethod.POST, new URI(urlString));
        System.out.println("functionRequest: " + functionRequest.toString());
        ResponseEntity<String> functionResponse = new RestTemplate().exchange(functionRequest, String.class);
        Assertions.assertEquals(200, functionResponse.getStatusCode().value());
        System.out.println(functionResponse.getHeaders());
        System.out.println(functionResponse.getBody());
    }

    @Test
    void verify() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException, CertificateException {
        final String key = "-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCI2+xZhm6ghDU2kxKMGBjDQOduUOUwcslFITLxPni6b88SjgBq+WkcOISc13GvhaXJa+GEaDGmJCYQFVZ2oXUNcoAJpZGtRNfLDOKlEwKYfcv9GwD10IoOvU1E3P8IDCE8G3SC4bH/H0DW6dU/0uAGwAC3KyiVEZshWz5cv2hJ1GnxFgoyVwYUgGT1KX89ltZUTNMwCBQpIQHl/zpNT6BEicxMl0P4ZcKoZd90Iw9yJTm1cTcDrmdMy+vHRCd2HUSZZ+ydqSMGGWAbjRfFU7erwj2vgpQSLb8E221yFXMxb39Y1rVrLn+jbrDbjclKzhGzs46pPJgh0A9M5FgrhLzHAgMBAAECggEAAME0HXSrUxrhIqSCLqzKiveADzcTYuACXu1rvX7UGM5MowdbcAhhQ85f+zyignUUA/dVuztj3EziVNmS330ACz69ZZ0Fhgh7wPSyPBAA+XXmh3licpIsbYZhUObmSFVHMNcQUZ4MmdT1sGAbuyPFKBeSj9ZrsKuNlaW0kCH4ew4jWUsx3Y/SEEdwtLB3jgEKT0vMszp+oPFp3n4kdRvvfl7AAG3pK9JRqW7coHBIoxhURpKqLpiZEK1c65R5Pudd4dIHJ9v4j529jxZOU26sOWHGVcQNie2E3X0iOw4Mc0id+SQHAwBKZOOYRqjGRNriOExBaA+exvjpWI9KIRolCQKBgQC9gYC/ezqoymeAXmaQ5X2DzaPHmvlI4d/aNTcWroySAt8c4IsoxtIJ0rUal4P6KuRdD71Rp060/SmUsz0RmXlmHbk0eD5n1E5VoG3m2MxWuaHu201C3/B9voxfo9pgyEpezPKpEB5NoX7pp49D4IDyOUAJk/O9AzklSluIraT9rQKBgQC44WKaOT7qCkWHs9LEW+13H030C3+qYkinr6PoFOu2oPsIaAA0mciBne0UIGdaSYtClAk2x1mPsKi3mMcsZ1PVtWgK0gZFndECPpUNaH39B2Cvfafa6hZxJ2zcp1tMZvjiqn3Ll3wCtCq89uXr0prY8Gj2Vm84xP2KwZ+yvQHKwwKBgEONoJmhkf2NeWvXOvS3+hA8BAApjGegrS2Z/rNFMbLy9xnSKYk1prX9uLVsAY3yMEnETJaI75OxE1uAsWpOrWnrepPrsUNN+Uao08SQz/ayYblFz7rhHVeVz3Bgdn49p9U3deEyb7r4sMcWBgoKQ60VH3DKnv5n4b0bTpngXIpZAoGBAJICfkrqlwNjJVJs9DHboAkKEhiA1EyN3m+ASWRK0XWkYV1cNX1VToL/ZHMWvEkT+AWWwEgg3Fyc2kJVSEeLOyx2Xjrdb9KfNqgdIL48HfQtVXCDPoOniB3JUzJYgcQvNrRcjYiylF/WRkKCg0bhRyW5iEu0K5acDNj+3c7dcoLdAoGBAJxK4eG0tSAKEGO++eRDJE0qNqe74I/VfDfFKxWdXGNPDVvQWZRe7VNHy/h5gV5+U84L9VaB1we3QECRwTD2OYNzlsAaUgQdBKrAR4VhbWohh3XRZlTXRDX9h2geZBG0+IP4y35eVXpthMOEAAJrvS00koK43hzWMMyJQcxRMyWZ-----END PRIVATE KEY-----";
//        final String publicKey = "iNvsWYZuoIQ1NpMSjBgYw0DnblDlMHLJRSEy8T54um/PEo4AavlpHDiEnNdxr4WlyWvhhGgxpiQmEBVWdqF1DXKACaWRrUTXywzipRMCmH3L/RsA9dCKDr1NRNz/CAwhPBt0guGx/x9A1unVP9LgBsAAtysolRGbIVs+XL9oSdRp8RYKMlcGFIBk9Sl/PZbWVEzTMAgUKSEB5f86TU+gRInMTJdD+GXCqGXfdCMPciU5tXE3A65nTMvrx0Qndh1EmWfsnakjBhlgG40XxVO3q8I9r4KUEi2/BNttchVzMW9/WNa1ay5/o26w243JSs4Rs7OOqTyYIdAPTORYK4S8xw==";
//        final String publicKey2 = "iNvsWYZuoIQ1NpMSjBgYw0DnblDlMHLJRSEy8T54um_PEo4AavlpHDiEnNdxr4WlyWvhhGgxpiQmEBVWdqF1DXKACaWRrUTXywzipRMCmH3L_RsA9dCKDr1NRNz_CAwhPBt0guGx_x9A1unVP9LgBsAAtysolRGbIVs-XL9oSdRp8RYKMlcGFIBk9Sl_PZbWVEzTMAgUKSEB5f86TU-gRInMTJdD-GXCqGXfdCMPciU5tXE3A65nTMvrx0Qndh1EmWfsnakjBhlgG40XxVO3q8I9r4KUEi2_BNttchVzMW9_WNa1ay5_o26w243JSs4Rs7OOqTyYIdAPTORYK4S8xw";
//        final String publicJWK = "iNvsWYZuoIQ1NpMSjBgYw0DnblDlMHLJRSEy8T54um_PEo4AavlpHDiEnNdxr4WlyWvhhGgxpiQmEBVWdqF1DXKACaWRrUTXywzipRMCmH3L_RsA9dCKDr1NRNz_CAwhPBt0guGx_x9A1unVP9LgBsAAtysolRGbIVs-XL9oSdRp8RYKMlcGFIBk9Sl_PZbWVEzTMAgUKSEB5f86TU-gRInMTJdD-GXCqGXfdCMPciU5tXE3A65nTMvrx0Qndh1EmWfsnakjBhlgG40XxVO3q8I9r4KUEi2_BNttchVzMW9_WNa1ay5_o26w243JSs4Rs7OOqTyYIdAPTORYK4S8xw";
//        final String cert2 = "MIIDSjCCAjKgAwIBAgIIQNb53mDWmp4wDQYJKoZIhvcNAQEFBQAwSDFGMEQGA1UEAxM9d2VhdGhlci1jbGllbnQtYXBwbGljYXRpb24ubWlrZXMtZGVtby5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAeFw0yMzAyMTgxODQ2MDRaFw0yNTAzMTEwOTExNDlaMEgxRjBEBgNVBAMTPXdlYXRoZXItY2xpZW50LWFwcGxpY2F0aW9uLm1pa2VzLWRlbW8uaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoKPhN5crwJ96xrpkXcdY/3gMkEyYdEORwPp/TolSooMAlCbovGqjb/eFi8WlQzhG8Ond+5aVp7JggIgB6KbLHZ8vYUfpNI0/+G7cH4/FU6XPjBbTl109Q0MMnPSZrCV1Vj9Y3O6oUPmmk19K6iJ7tIm5DcM6xjEj99slKp5ns50pgaRz4FUMKCRjo4cOIvnSo8mdWZYiusAxvkIpnF7dIzOeoIvSPK3om2U3e6gun6T+b01EdF16kvP7FgxdvU1qMe3QS+U+aF6xdFO8JpAge9aPIu3XeaAN4V2OAKLXvZMiIvt3Flx4K22wxnbEUJQ9DWxgxdcE8hNqUfUhEuA4BAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAB2LhujmZQ+gt7DdB1olST2sKQqNkTAG5qM6q8InMukUA1lutiYiCG3b4KhK5e2NdxkOJlnjGoOOgTmCK0yOo3Lqs7i3zdPCY1+SJ4Mk7SGcn+5PpANAGGGBjyWX1selhJRN7I0k8WfbelsIIMp6ZcijQy2G3gy39RNNplofCpC+4dbYFMdtxUgqFa3qZMQTB5VH544V9o9ZAX9fxN7I4qiTxQgwOPET4Om4krMoeC6o14VhyK+vFFJ0xSGRkE+6iaHi96uGPIZhTbv1XvNkzeKyDF8CnRBxThdy1p3CIp0FOr1lwj+2lJnTL1lfIfGBqVIl4KgddPbKLiBnZnUwVi";

        final String cert1 = "MIIC/DCCAeSgAwIBAgIII4EdPdvmfEMwDQYJKoZIhvcNAQEFBQAwIDEeMBwGA1UEAxMVMTAzMzg4ODkwNzM3NT" +
                "AxMTI1MTE5MCAXDTIzMDIxODE4NDcxMloYDzk5OTkxMjMxMjM1OTU5WjAgMR4wHAYDVQQDExUxMDMzODg4OTA3Mzc1MDExMjUxMTkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCI2+xZhm6ghDU2kx" +
                "KMGBjDQOduUOUwcslFITLxPni6b88SjgBq+WkcOISc13GvhaXJa+GEaDGmJCYQFVZ2oXUNcoAJpZGtRNfLDOKlEwKYfcv9GwD10IoOvU1E3P8IDCE8G3SC4bH/H0DW6dU/0uAGwAC3KyiVEZshWz5cv2hJ1Gnx" +
                "FgoyVwYUgGT1KX89ltZUTNMwCBQpIQHl/zpNT6BEicxMl0P4ZcKoZd90Iw9yJTm1cTcDrmdMy+vHRCd2HUSZZ+ydqSMGGWAbjRfFU7erwj2vgpQSLb8E221yFXMxb39Y1rVrLn+jbrDbjclKzhGzs46pPJgh0A9M" +
                "5FgrhLzHAgMBAAGjODA2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQAHpobLFsDWJoyPOPO+302epkV5BPHpa4a5N7kAnw" +
                "hzDl4DT7VPZPB+njKiA3iiSeDnEvP0q/FqtWtqIBLIU0qQdQ10g6WYQ0wvPqC61D5NpStweYhVK5kNbHXCsT7uQpdQL00ZiPZArnaSdMj4LqkPpqOIZyR5zzVE+sH3AK5qdS1RxgEVj1hAUB27U6Jj4koxvYfl7+" +
                "Rd75oFa9DQR43Qm+LcMrw6KdyXVPR07obUXJr4r8h6+/b0c85uueX4c3ff+l9ywZ9iZ2ZJPF6KFYeeriNC+OjQNUMSnY3lUxN5+V/gQd4e7KaP0xDw+9gtuLM2CFyY4si+xX4yaOc9vPP8";
        String email = "weather-client-application@mikes-demo.iam.gserviceaccount.com";
        String urlString = "https://weather-xdqrgy4k7a-lm.a.run.app";
        String audience = "https://www.googleapis.com/oauth2/v4/token";
        String targetAudience = urlString;
        String jwt = new JwtHelper().generateJWT(
                email, email, audience, targetAudience, key
        );
//        String jwt = idToken();
        System.out.println("JWT:\n" + jwt);
        new JwtHelper().verifyKey(jwt, cert1);
    }
}