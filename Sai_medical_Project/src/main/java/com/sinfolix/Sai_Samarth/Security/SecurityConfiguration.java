package com.sinfolix.Sai_Samarth.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> {
                authorize.requestMatchers("/login").permitAll();
                authorize.anyRequest().fullyAuthenticated();
                })
                .oauth2Login(oauth2login -> {
                oauth2login.successHandler(( request,  response,  authentication) -> response.sendRedirect("/home"));
                })
                 .oauth2Login(oauth2login -> {
                     oauth2login.defaultSuccessUrl("/loginSuccess",true);
                 })
                .sessionManagement(session->{
                    session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
                })
                .rememberMe(remember->remember.disable())
                .logout(logout -> logout
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
        )
//                .exceptionHandling(exception->{
//                   exception.authenticationEntryPoint((request, response, authException) -> {
//                       response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//                       response.getWriter().write("Unauthorized: Authentication token required.");
//                   });
//                })
                 .build();

    }
}