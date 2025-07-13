package com.expensemanagement.controller;

import com.expensemanagement.entities.Customer;
import com.expensemanagement.service.CustomerService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.regex.Pattern;

@Controller
@RequiredArgsConstructor
public class WelcomeController {

    private final CustomerService customerService;
    private final PasswordEncoder passwordEncoder;
    private final String regex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$&*])(?=.*[0-9]).+$";

    @GetMapping({"/home","/"})
    public String welcomeMessage(HttpServletRequest request, Authentication authentication) {
        Customer customer = customerService.loadCustomerByUsername(authentication.getName());
        request.setAttribute("firstName", customer.getFirstName());
        request.setAttribute("lastName", customer.getLastName());
        return "home";
    }

    @GetMapping("/profile")
    public String userDetails(Model model) {
        SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        Customer customer = customerService.loadCustomerByUsername(securityContextHolderStrategy.getContext().getAuthentication().getName());
        model.addAttribute("userdata",customer);
        return "profile";
    }

    @PostMapping("/changePwd")
    public String changePwd(@RequestParam String password,
                            @RequestParam String confirmPassword,
                            Model model) {
        if(!password.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords are not matching");
            return "change-password";
        }
        if(!Pattern.matches(regex, password)) {
            model.addAttribute("error", "Password must contain atleast one uppercase letter, " +
                    "one lowercase letter, one numeric digit and one special symbol from (!@#$&*)");
            return "change-password";
        }
        SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        Customer customer = customerService.loadCustomerByUsername(securityContextHolderStrategy.getContext().getAuthentication().getName());
        customer.setPassword(passwordEncoder.encode(password));
        customerService.saveCustomer(customer);
        return "redirect:/changePwd?resetSuccess";
    }

    @GetMapping("/changePwd")
    public String getChangePwdPage() {
        return "change-password";
    }
}
