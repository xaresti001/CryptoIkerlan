package com.aresti.cryptoikerlan.controller;

import com.aresti.cryptoikerlan.pojo.RootCertificateAndKeyPair;
import com.aresti.cryptoikerlan.requestsAndResponses.CN;
import com.aresti.cryptoikerlan.requestsAndResponses.CRT;
import com.aresti.cryptoikerlan.requestsAndResponses.CSR;
import com.aresti.cryptoikerlan.requestsAndResponses.VALID;
import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;


import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

@RestController
@RequestMapping("/crypto")
public class CryptoController {

    private static final String SIG_ALGORITHM = "SHA256withRSA";
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";

    private RootCertificateAndKeyPair storedRootCertificateAndKeyPair = null;


    @PostMapping("/ca")
    public ResponseEntity<CRT> generateCACertificateAPIPost(@RequestBody CN cn) throws CertificateException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, OperatorCreationException {
        // Generate CA Certificate
        storedRootCertificateAndKeyPair = generateCACertificate(cn.getCommon_name());
        CRT crtResponse = new CRT(serializePEMCertificateBase64(storedRootCertificateAndKeyPair.getCertificate()));
        return ResponseEntity.ok(crtResponse);
    }

    @PostMapping("/crt")
    public ResponseEntity<CRT> issueCertificateAPIPost(@RequestBody CSR csr) throws IOException, CertificateException, NoSuchAlgorithmException, OperatorCreationException {
        if (storedRootCertificateAndKeyPair != null){
            // Parse to PKCS10CertificationRequest object
            Reader pemCSRReader = new StringReader(csr.getCsr());
            PEMReader reader = new PEMReader(pemCSRReader);
            PKCS10CertificationRequest certificateSigningRequest = new PKCS10CertificationRequest((CertificationRequest) reader.readObject());

            // Issue Certificate
            X509Certificate issuedCertificate = issueCertificate(certificateSigningRequest);
            CRT crtResponse = new CRT(serializePEMCertificateBase64(issuedCertificate));
            return ResponseEntity.ok(crtResponse);
        }
        // There is no CA Created
        else{
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/validate")
    public ResponseEntity<VALID> validateCertificateAPIPost(@RequestBody CRT crt) throws IOException {
        if (storedRootCertificateAndKeyPair != null){
            // Parse to X509Certificate object
            Reader pemCSRReader = new StringReader(crt.getCrt());
            PEMReader reader = new PEMReader(pemCSRReader);
            X509Certificate crtToValidate = (X509Certificate)reader.readObject();
            boolean valid = validateCertificate(crtToValidate);
            return ResponseEntity.ok(new VALID(valid));
        }
        // There is no CA Created
        else{
            return ResponseEntity.badRequest().build();
        }
    }

    private boolean validateCertificate(X509Certificate crtToValidate){
        // Dummy init of variable
        boolean valid = true;

        // Validate certificate with current CA
        try {
            crtToValidate.verify(storedRootCertificateAndKeyPair.getKeyPair().getPublic());
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException |
                 SignatureException e) {
            valid = false;
        }
        return valid;
    }

    private X509Certificate issueCertificate(PKCS10CertificationRequest csr) throws NoSuchAlgorithmException, CertIOException, CertificateException, OperatorCreationException {
        // Set random rootSerialNumber
        BigInteger issuedSerialNumber = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Set validity - 1 year
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 1);

        // Get rootIssuer name from rootCert and setup certificate builder
        X500Name rootCertificateIssuer = new X500Name(storedRootCertificateAndKeyPair.getCertificate().getSubjectX500Principal().getName());
        X509v3CertificateBuilder issuedCertificateBuilder = new X509v3CertificateBuilder(rootCertificateIssuer, issuedSerialNumber, new Date(), calendar.getTime(), csr.getSubject(), csr.getSubjectPublicKeyInfo());

        // Add basicConstraint to mark it is not a CA certificate and add Issues identifier
        JcaX509ExtensionUtils issuedCertificateExtensionUtils = new JcaX509ExtensionUtils();
        issuedCertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        issuedCertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertificateExtensionUtils.createAuthorityKeyIdentifier(storedRootCertificateAndKeyPair.getCertificate()));
        issuedCertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertificateExtensionUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Create and return X509Certificate
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertificateBuilder.build(new JcaContentSignerBuilder(SIG_ALGORITHM).setProvider(BC_PROVIDER).build(storedRootCertificateAndKeyPair.getKeyPair().getPrivate())));
    }

    private RootCertificateAndKeyPair generateCACertificate(String commonName) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, SignatureException, InvalidKeyException, OperatorCreationException {
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Setup keyPairGenerator and generate rootKeyPair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();

        // Set validity - 1 year
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 1);

        // Set random rootSerialNumber
        BigInteger rootSerialNumber = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertificateIssuer = new X500Name("CN=" + commonName);
        X500Name rootCertificateSubject = rootCertificateIssuer;

        X509v3CertificateBuilder rootCertificateBuilder = new JcaX509v3CertificateBuilder(rootCertificateIssuer, rootSerialNumber, new Date(), calendar.getTime(), rootCertificateSubject, rootKeyPair.getPublic());

        // Add basicConstraint as CA certificate mark
        JcaX509ExtensionUtils rootCertificateExtensionUtils = new JcaX509ExtensionUtils();
        rootCertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertificateExtensionUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Create X509Certificate
        X509Certificate rootCertificate = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertificateBuilder.build(new JcaContentSignerBuilder(SIG_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate())));

        return new RootCertificateAndKeyPair(rootCertificate, rootKeyPair);
    }

    private String serializePEMCertificateBase64(X509Certificate certificate) throws CertificateEncodingException, IOException {
        ByteOutputStream byteOutputStream = new ByteOutputStream();
        PrintStream printStream = new PrintStream(byteOutputStream);
        BASE64Encoder encoder = new BASE64Encoder();
        printStream.println(X509Factory.BEGIN_CERT);
        encoder.encodeBuffer(certificate.getEncoded(), printStream);
        printStream.println(X509Factory.END_CERT);
        printStream.flush();
        System.out.println(byteOutputStream);
        return byteOutputStream.toString();
    }

    // EXAMPLE CSR CREATOR - NOT IN USE IN CODE
    // Created for testing purposes for certificate signing in method issueCertificate above.
    // Call this method: CSR csr = new CSR(createPKCS10CertificationRequest());
    private String createPKCS10CertificationRequest() throws NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, IOException {
        // Setup keyPairGenerator and create certKeyPair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);
        KeyPair certKeyPair = keyPairGenerator.generateKeyPair();

        // CN for cert
        X500Name certSubject = new X500Name("CN=issued-cert");
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(certSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIG_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(storedRootCertificateAndKeyPair.getKeyPair().getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Serialize CSR PEM format, using \r\ as line separator
        ByteOutputStream byteOutputStream = new ByteOutputStream();
        PrintStream printStream = new PrintStream(byteOutputStream);
        BASE64Encoder encoder = new BASE64Encoder();
        printStream.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
        encoder.encodeBuffer(csr.getEncoded(), printStream);
        printStream.println("-----END NEW CERTIFICATE REQUEST-----");
        printStream.flush();
        return byteOutputStream.toString();
    }
}
