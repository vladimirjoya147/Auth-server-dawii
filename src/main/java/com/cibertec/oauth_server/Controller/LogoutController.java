package com.cibertec.oauth_server.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LogoutController {

    @GetMapping("/logout")
    public String logout(
            @RequestParam(value = "id_token_hint", required = false) String idTokenHint,
            @RequestParam(value = "post_logout_redirect_uri", required = false) String postLogoutRedirectUri,
            @RequestParam(value = "client_id", required = false) String clientId,
            HttpServletRequest request,
            HttpServletResponse response) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        SecurityContextHolder.clearContext();

        if (isValidPostLogoutRedirectUri(postLogoutRedirectUri)) {
            return "redirect:" + postLogoutRedirectUri;
        }

        return "redirect:/login?logout";
    }

    private boolean isValidPostLogoutRedirectUri(String redirectUri) {
        if (redirectUri == null) return false;
        return redirectUri.startsWith("http://localhost:4200/");
    }
}