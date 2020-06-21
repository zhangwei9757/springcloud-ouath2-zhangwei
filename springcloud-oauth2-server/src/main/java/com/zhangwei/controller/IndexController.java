package com.zhangwei.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zhangwei
 * @date 2020-6-19 20:42:1
 **/
@RestController
public class IndexController {

    @PostMapping("/index")
    public String index() {
        return "index";
    }
}
