package com.example.springbootjwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

@Slf4j
public class JwtHelper {

    private static final int EXPIRY_DURATION = 15;

    public String generateJWT(String jwtSubject, String jwtIssuer, String jwtAudience, String targetAudience, String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String jwt = null;
        // Set the issue and expiry dates.
        Calendar calendar = Calendar.getInstance();
        Date issueDate = calendar.getTime();
        calendar.add(Calendar.MINUTE, EXPIRY_DURATION);
        Date expiryDate = calendar.getTime();
        RSAPrivateKey serviceAccountPK = privateKeyFromString(privateKey);
        jwt = buildJWT(jwtSubject, jwtIssuer, jwtAudience, targetAudience, issueDate, expiryDate, serviceAccountPK);
        return jwt;
    }

    private RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] publicKeyDecoded = Base64.getDecoder().decode(publicKey);
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicKeyDecoded);
        byte[] decode = Base64.getDecoder().decode(publicKey);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(decode),
                new BigInteger(Base64.getDecoder().decode("AQAB")));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicRSAKey = kf.generatePublic(keySpec);
        return (RSAPublicKey) publicRSAKey;
    }

    public DecodedJWT verifyKey(String jwtToken, String publicKey) throws CertificateException {
        var decode = Base64.getDecoder().decode(publicKey);
        var certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(decode));
        var publicKeyObj = (RSAPublicKey) certificate.getPublicKey();
//        var publicKeyObj = getPublicKey(publicKey);
        JWTVerifier verifier = JWT.require(Algorithm.RSA256(publicKeyObj, null))
                .build();
        DecodedJWT jwt = verifier
                .verify(jwtToken);
        System.out.println("Decoded jwt: \nHEADER:"
                + new String(Base64.getDecoder().decode(jwt.getHeader()))
                + "\nPAYLOAD: "
                + new String(Base64.getDecoder().decode(jwt.getPayload()))
                + "\nSIGNATURE: " + jwt.getSignature());
        return jwt;
    }

    private RSAPrivateKey privateKeyFromString(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read in the key into a String
        StringBuilder pkcs8Lines = new StringBuilder();
        BufferedReader rdr = new BufferedReader(new StringReader(privateKey));
        String line;
        while ((line = rdr.readLine()) != null) {
            pkcs8Lines.append(line);
        }

        // Remove the "BEGIN" and "END" lines, as well as any whitespace
        String pkcs8Pem = pkcs8Lines.toString();
        pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
        pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

        // Base64 decode the result
//        System.out.println("Decode " + pkcs8Pem);
        byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);

        // extract the private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Pem.getBytes(StandardCharsets.UTF_8));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateKey privKey = (RSAPrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }

    private String buildJWT(String jwtSubject,
                            String jwtIssuer,
                            String jwtAudience,
                            String targetAudience,
                            Date issueDate, Date expiryDate, RSAPrivateKey key) {
        return JWT.create()
                .withSubject(jwtSubject)
                .withNotBefore(issueDate)
                .withIssuedAt(issueDate)
                .withExpiresAt(expiryDate)
                .withIssuer(jwtIssuer)
                .withAudience(jwtAudience)
                .withClaim("target_audience", targetAudience)
                .sign(Algorithm.RSA256(null, key));
    }


}
