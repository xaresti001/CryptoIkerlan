package com.aresti.cryptoikerlan.requestsAndResponses;

public class CSR {
    private String csr;

    public CSR(String csr) {
        this.csr = csr;
    }

    public CSR() {
    }

    public String getCsr() {
        return csr;
    }

    public void setCsr(String csr) {
        this.csr = csr;
    }
}
