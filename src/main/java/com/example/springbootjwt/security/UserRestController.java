package com.example.springbootjwt.security;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Hashtable;
import java.util.Map;

public class UserRestController {

//    @GetMapping("/user/info")
//    public Map<String, Object> getUserInfo(@AuthenticationPrincipal OAuth2ResourceServerProperties.Jwt principal) {
//        Map<String, String> map = new Hashtable<>();
//        map.put("user_name", principal.getClaimAsString("preferred_username"));
//        map.put("organization", principal.getClaimAsString("organization"));
//        return Collections.unmodifiableMap(map);
//    }
}
