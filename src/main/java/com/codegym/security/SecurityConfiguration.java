package com.codegym.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration  extends WebSecurityConfigurerAdapter {

    @Override
    protected void  configure(AuthenticationManagerBuilder managerBuilder) throws Exception {
        managerBuilder.inMemoryAuthentication()
                .withUser("quocthien").password("{noop}12345").roles("USER")
                .and()
                .withUser("vantho").password("{noop}12345").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security.authorizeHttpRequests()
                . requestMatchers("/").permitAll()
                .requestMatchers("/user**").hasRole("USER")
                .requestMatchers("/admin**").hasRole("ADMIN")
                .and()
                .formLogin()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"));

    }
}
