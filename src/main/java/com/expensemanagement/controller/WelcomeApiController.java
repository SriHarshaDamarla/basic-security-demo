package com.expensemanagement.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class WelcomeApiController {
  @GetMapping("/welcome")
  public String welcomeMessage() {
    return "Welcome API!";
  }
}
