package com.example.springbootjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                .authorizeHttpRequests((custom)->{
                    try {
                        custom.requestMatchers(HttpMethod.GET, "/user/info", "/api/foos/**")
                                .hasAuthority("SCOPE_read")
                                .requestMatchers(HttpMethod.POST, "/api/foos")
                                .hasAuthority("SCOPE_write")
                                .anyRequest()
                                .authenticated()
                                .and()
                                .oauth2ResourceServer((oauth2custom)->{
                                    oauth2custom.jwt((jwtcustom ->{
                                    }));
                                });
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });




        http.authorizeHttpRequests().requestMatchers("/**").hasRole("USER").and().formLogin();
        return http.build();
    }


}