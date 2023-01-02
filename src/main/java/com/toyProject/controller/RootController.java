package com.toyProject.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class RootController {

    @GetMapping(value = { "/", "/index" })
    public String index(Model model) {

        model.addAttribute("test","TEST!!!!");
        return "pages/index";
    }

}
