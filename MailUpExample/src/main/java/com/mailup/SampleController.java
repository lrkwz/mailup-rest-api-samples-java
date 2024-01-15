package com.mailup;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class SampleController {
    @RequestMapping("/")
    public ModelAndView viewIndex(final ModelAndView modelAndView) {
        modelAndView.setViewName("index");
        return modelAndView;
    }

    @RequestMapping("/test")
    public ModelAndView viewTestPage(final ModelAndView modelAndView) {
        modelAndView.setViewName("test");
        return modelAndView;
    }
}
