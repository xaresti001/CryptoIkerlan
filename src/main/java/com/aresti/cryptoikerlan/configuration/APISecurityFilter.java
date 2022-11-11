package com.aresti.cryptoikerlan.configuration;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.http.HttpServletRequest;

public class APISecurityFilter extends AbstractPreAuthenticatedProcessingFilter {

    private String headerName;

    public APISecurityFilter(String principalRequestHeader) {
        this.headerName = principalRequestHeader;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getHeader(headerName);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }
}