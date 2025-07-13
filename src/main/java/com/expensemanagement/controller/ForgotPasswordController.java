package com.expensemanagement.controller;

import com.expensemanagement.entities.Customer;
import com.expensemanagement.service.CustomerService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

@Controller
@RequestMapping("/fpwd")
@RequiredArgsConstructor
public class ForgotPasswordController {

    private final CustomerService customerService;
    private final PasswordEncoder passwordEncoder;
    private final Map<String,String> map = new HashMap<>();
    private final String regex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*[!@#$&*])(?=.*[0-9]).+$";
    private final Map<String, LocalDateTime> idWithExpiry = new HashMap<>();

    @GetMapping("/generate")
    public String generateResetUrl(@RequestParam(required = false) String username) {
        if(username == null) {
            return "generate";
        }
        if (!customerService.isUserPresentWithUsername(username)) {
            return "redirect:generate?error";
        }
        String uuid = UUID.randomUUID().toString();
        System.out.println("id: "+uuid);
        map.put(uuid, username);
        idWithExpiry.put(uuid, LocalDateTime.now().plusMinutes(5));
        return "redirect:/login?generated";
    }

    @PostMapping("/reset/{id}")
    public String resetPassword(@PathVariable String id,
                                @RequestParam String password,
                                @RequestParam String confirmPassword,
                                Model model) {
        if(!password.equals(confirmPassword)) {
            model.addAttribute("error", "Passwords are not matching");
            model.addAttribute("id", id);
            return "forgot-password";
        }
        if(!Pattern.matches(regex, password)) {
            model.addAttribute("error", "Password must contain atleast one uppercase letter, " +
                                                                "one lowercase letter, one numeric digit and one special symbol from (!@#$&*)");
            model.addAttribute("id", id);
            return "forgot-password";
        }
        Customer customer = customerService.loadCustomerByUsername(map.get(id));
        customer.setPassword(passwordEncoder.encode(password));
        customerService.saveCustomer(customer);
        map.remove(id);
        idWithExpiry.remove(id);
        return "redirect:/login?resetSuccess";
    }

    @GetMapping("/reset/{id}")
    public String getResetPassPage(@PathVariable String id, Model model) {
        LocalDateTime expiryTime = idWithExpiry.get(id);
        if (expiryTime == null || LocalDateTime.now().compareTo(expiryTime) > 0) {
            return "redirect:/login?invalidId";
        }
        model.addAttribute("id",id);
        return "forgot-password";
    }
}
