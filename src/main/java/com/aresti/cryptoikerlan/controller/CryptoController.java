package com.aresti.cryptoikerlan.controller;

import com.aresti.cryptoikerlan.pojo.RootCertificateAndKeyPair;
import com.aresti.cryptoikerlan.requestsAndResponses.CN;
import com.aresti.cryptoikerlan.requestsAndResponses.CRT;
import com.aresti.cryptoikerlan.requestsAndResponses.CSR;
import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;


import java.io.IOException;
import java.io.PrintStream;
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
        System.out.println("Received CN: " + cn.getCommon_name());
        storedRootCertificateAndKeyPair = generateCACertificate(cn.getCommon_name());
        CRT crtResponse = new CRT(serializePEMCertificate(storedRootCertificateAndKeyPair.getCertificate()));
        return ResponseEntity.ok(crtResponse);
    }

    @PostMapping
    public ResponseEntity<CRT> issueCertificateAPIPost(@RequestBody CSR csr){
        if (storedRootCertificateAndKeyPair != null){

        }
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

        // Identify Algorithm
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_ALGORITHM);
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

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

    private String serializePEMCertificate(X509Certificate certificate) throws CertificateEncodingException, IOException {
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









        /*private HashMap<PrivateKey, X509Certificate> generateCACertificate2(String commonName) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException, SignatureException, InvalidKeyException {
        // Generador de certificados, RSA SHA256
        CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
        certAndKeyGen.generate(2048);
        // Obtener clave privada
        PrivateKey rootPrivateKey = certAndKeyGen.getPrivateKey();

        certAndKeyGen.
        // Genera certificado que actuará de CA
        X509Certificate rootCert = certAndKeyGen.getSelfCertificate(
                new X500Name("CN="+commonName), (long)365*24*60*60);
        HashMap<PrivateKey, X509Certificate> output = new HashMap<>();
        output.put(rootPrivateKey, rootCert);
        ByteOutputStream bos = new ByteOutputStream();
        PrintStream out = new PrintStream(bos);
        BASE64Encoder encoder = new BASE64Encoder();
        out.println(X509Factory.BEGIN_CERT);
        encoder.encodeBuffer(rootCert.getEncoded(), out);
        out.println(X509Factory.END_CERT);
        out.flush();
        System.out.println(bos.toString());


        return output;
    }*/



}
