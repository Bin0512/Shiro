package com.imooc.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.imooc.user.User;

@Controller
public class UserController {
	
	@RequestMapping(value = "/subLogin",method = RequestMethod.POST)
	public String subLogin(User user) {
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(),user.getPassword());
		try {
			subject.login(token);
		} catch (AuthenticationException e) {
			// TODO: handle exception
			return "failure";
		}
		return "success";
	}
}
