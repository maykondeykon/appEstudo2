package com.mkdk.app;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) {
        try {
            http.csrf().disable();
            http.userDetailsService(userDetailsService())
                    .authorizeRequests()
                    .antMatchers("/").permitAll()
                    .antMatchers("/**.xhtml").permitAll()
                    .antMatchers("/javax.faces.resource/**").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin()
                    .loginPage("/index.xhtml")
                    .permitAll()
                    .failureUrl("/index.xhtml?error=true")
                    .defaultSuccessUrl("/dashboard.xhtml")
                    .and()
                    .logout()
                    .logoutSuccessUrl("/index.xhtml")
                    .deleteCookies("JSESSIONID");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
        userDetailsManager.createUser(User.withDefaultPasswordEncoder().username("admin").password("123").authorities("ROLE_ADMIN").build());
        userDetailsManager.createUser(User.withDefaultPasswordEncoder().username("user").password("321").authorities("ROLE_USER").build());
        return userDetailsManager;
    }
}
