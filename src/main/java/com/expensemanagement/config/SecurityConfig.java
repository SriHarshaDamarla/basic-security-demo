package com.expensemanagement.config;

import com.expensemanagement.entities.Customer;
import com.expensemanagement.repositories.CustomerRepo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomerRepo customerRepo;

    @Bean
    SecurityFilterChain httpSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .securityContext(sc -> sc.requireExplicitSave(false))
                .cors(corsConfig -> {
                    CorsConfigurationSource corsSource = new CorsConfigurationSource() {
                        @Override
                        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                            CorsConfiguration corsConfiguration = new CorsConfiguration();
                            corsConfiguration.addAllowedOrigin("http://127.0.0.1:3000");
                            corsConfiguration.setAllowCredentials(true);
                            corsConfiguration.addAllowedMethod("*");
                            corsConfiguration.addAllowedHeader("*");
                            corsConfiguration.setMaxAge(3600L);
                            return corsConfiguration;
                        }
                    };
                    corsConfig.configurationSource(corsSource);
                })
                .sessionManagement(sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .authorizeHttpRequests(
                        authorizer ->
                                authorizer
                                        .requestMatchers("/styles/**","/scripts/**","/login**","/signup","/registerUser","/fpwd/**").permitAll()
                                        .anyRequest().authenticated()
                )
                .csrf(csrfConfigurer -> csrfConfigurer.ignoringRequestMatchers("/api/**"))
                .formLogin(
                        loginConfigurer -> loginConfigurer.loginPage("/login")
                )
                .logout(loc -> loc
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                )
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public UserDetailsService jpaUserDetailsService() {
        return username -> {
            Customer customer = customerRepo.findByUserId(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Customer with " + username + " is not found"));
            return User
                    .builder()
                    .username(username)
                    .password(customer.getPassword())
                    .authorities(customer.getRole()).build();
        };
    }

}
