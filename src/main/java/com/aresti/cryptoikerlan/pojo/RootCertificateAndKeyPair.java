package com.aresti.cryptoikerlan.pojo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class RootCertificateAndKeyPair {
    private X509Certificate certificate;
    private KeyPair keyPair;

    public RootCertificateAndKeyPair(X509Certificate certificate, KeyPair keyPair) {
        this.certificate = certificate;
        this.keyPair = keyPair;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
