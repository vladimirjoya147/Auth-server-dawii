package com.cibertec.oauth_server.Controller;

import ch.qos.logback.core.model.Model;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class ConsentController {

    /*@GetMapping("/oauth2/consent")
    public String consent(@RequestParam Map<String, String> parameters,
                          Model model,
                          Authentication authentication) {

        String authorizationRequestUri = UriComponentsBuilder
                .fromPath("/oauth2/authorize")
                .queryParams(new LinkedMultiValueMap<>(
                        parameters.entrySet().stream()
                                .collect(Collectors.toMap(
                                        Map.Entry::getKey,
                                        e -> Collections.singletonList(e.getValue())
                                ))
                ))
                .build()
                .toUriString();

        return "redirect:" + authorizationRequestUri;
    }*/
}