package com.toyProject.controller;

import com.toyProject.dto.UserDto;
import com.toyProject.service.JoinService;
import com.toyProject.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;


@Controller
@RequiredArgsConstructor
public class RootController {

    private final UserService userService;

    @GetMapping(value = { "/", "/index" })
    public String index(Model model) {

        model.addAttribute("test","TEST!!!!");
        return "pages/index";
    }

    @GetMapping("/auth/signUpForm")
    public String signUpFrom(){

        return "pages/signUpForm";
    }

    @PostMapping("/auth/signUp")
    public String signUp(UserDto.Save dto){

        userService.createUser(dto);

        return "redirect:/";
    }

}
