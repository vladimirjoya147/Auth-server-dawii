package com.cibertec.oauth_server.Controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class DebugController {

    @GetMapping("/user/info")
    public Map<String, Object> userInfo(Authentication authentication) {
        Map<String, Object> info = new HashMap<>();
        info.put("authenticated", authentication != null && authentication.isAuthenticated());
        if (authentication != null) {
            info.put("username", authentication.getName());
            info.put("authorities", authentication.getAuthorities());
        }
        return info;
    }
}