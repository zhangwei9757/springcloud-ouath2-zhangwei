package com.zhangwei.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * @author zhangwei
 * @date 2020-6-19 20:42:1
 **/
@RestController
@RequestMapping("/oauth")
public class UserController {

    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

}