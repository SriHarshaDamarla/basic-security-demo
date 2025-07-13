package com.expensemanagement.controller;

import com.expensemanagement.bean.SignupForm;
import com.expensemanagement.service.CustomerService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class SignupController {

    private final CustomerService customerService;

    @GetMapping("/signup")
    public String signup(Model model) {
        model.addAttribute("signupForm", new SignupForm());
        return "signup";
    }

    @PostMapping("/registerUser")
    public String register(@Valid @ModelAttribute("signupForm") SignupForm form, BindingResult br, Model model) {
        if (!form.getPassword().equals(form.getConfirmPassword())) {
           br.addError(new FieldError(
                   "signupForm",
                   "confirmPassword",
                   "Password and Confirm Password fields are not matching"
                   )
           );
        }
        if(customerService.isUserPresentWithUsername(form.getUsername())) {
            br.addError(new FieldError(
                    "signupForm",
                    "username",
                    String.format("User %s already exists", form.getUsername())
                    )
            );
        }
        if(br.hasErrors()) {
            model.addAttribute("signupForm",form);
            return "signup";
        }
        customerService.registerUser(form);
        return "redirect:/login?signupSuccess";
    }
}
