package com.aresti.cryptoikerlan;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class CryptoIkerlanApplication {

    public static void main(String[] args) {
        SpringApplication.run(CryptoIkerlanApplication.class, args);
    }

}
