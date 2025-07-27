package com.expensemanagement.restController;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("/api")
public class RestLoginController {

    @PostMapping("/basic-login")
    public ResponseEntity<String> login(@RequestBody String text, Authentication authentication) {
        log.info("Received text: {}",text);
        return ResponseEntity.accepted().body(String.format("""
                {
                    "status": "SUCCESS",
                    "name": "%s"
                }
                """, authentication.getName()));
    }
}
