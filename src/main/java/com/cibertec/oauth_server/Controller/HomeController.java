package com.cibertec.oauth_server.Controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(Authentication authentication, HttpSession session) {
        SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(
                ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest(),
                ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse()
        );

        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            if (redirectUrl != null && redirectUrl.contains("/oauth2/authorize")) {
                return "redirect:" + redirectUrl;
            }
        }
        return "redirect:/user/info";
    }
}