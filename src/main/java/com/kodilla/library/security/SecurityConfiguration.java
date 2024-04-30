package com.kodilla.library.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.authorizeHttpRequests()
                .mvcMatchers("/v1/bean")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")
                .mvcMatchers("/v1/calc")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")
                .mvcMatchers("/csv/convert")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")
                .mvcMatchers("/csv/convert")
                .hasAnyRole("ADVANCED", "ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("basic").password("basic").roles("BASIC");
        auth.inMemoryAuthentication().withUser("advanced").password("advanced").roles("ADVANCED");
        auth.inMemoryAuthentication().withUser("admin").password("admin").roles("ADMIN");
    }

    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
}
