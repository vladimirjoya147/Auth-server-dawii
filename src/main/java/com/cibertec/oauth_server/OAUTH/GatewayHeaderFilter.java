package com.cibertec.oauth_server.OAUTH;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;


@Component
public class GatewayHeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        if (httpRequest.getRequestURI().startsWith("/login") ||
                httpRequest.getRequestURI().startsWith("/oauth2")) {

            chain.doFilter(request, response);
        } else {
            chain.doFilter(request, response);
        }
    }
}