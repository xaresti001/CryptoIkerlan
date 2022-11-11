package com.aresti.cryptoikerlan.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Configuration
@EnableWebSecurity
public class APISecurityConfiguration extends WebSecurityConfigurerAdapter {
    private String headerName = "X-API-Key";
    private String headerValue = "9ddaa525-bfc2-4f74-92e0-43b7a028aee1";

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        APISecurityFilter filter = new APISecurityFilter(headerName);
        filter.setAuthenticationManager(new AuthenticationManager() {

            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String principal = (String) authentication.getPrincipal();
                if (!headerValue.equals(principal))
                {
                    throw new BadCredentialsException("INVALID API KEY");
                }
                authentication.setAuthenticated(true);
                return authentication;
            }
        });
        httpSecurity.
                antMatcher("/crypto/**").
                csrf().disable().
                sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
                and().addFilter(filter).authorizeRequests().anyRequest().authenticated();
    }
}
