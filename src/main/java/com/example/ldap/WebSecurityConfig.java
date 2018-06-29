package com.example.ldap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    public LdapService ldapService;

    public CustomUserDetailsService customUserDetailsService;

    @Autowired
    @Qualifier("userDetailsService")
    public void setCustomUserDetailsService(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @Configuration
    @ConditionalOnProperty(prefix = "server.ssl", name = "enabled", havingValue = "true")
    public class SslAuthSecurityConfig  extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable();
            http.httpBasic().disable();

            http
                    .authorizeRequests()
                    .antMatchers("/chemists").hasRole("CHEMISTS")
                    .antMatchers("/mathematicians").hasRole("MATHEMATICIANS")
                    .anyRequest().fullyAuthenticated()
                    .and()
                    .x509().subjectPrincipalRegex("(.*)").userDetailsService(userDetailsService())
                    .and()
                    .anonymous().disable();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(customUserDetailsService);
        }
    }


    @Configuration
    @ConditionalOnProperty(prefix = "server.ssl", name = "enabled", havingValue = "false")
    public class BasicAuthSecurityConfig  extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable();

            http
                .authorizeRequests()
                    .antMatchers("/chemists").hasRole("CHEMISTS")
                    .antMatchers("/mathematicians").hasRole("MATHEMATICIANS")
                    .antMatchers("/login").permitAll()
                    .anyRequest().fullyAuthenticated()
                .and()
                .formLogin()
                .and()
                .httpBasic();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            ldapService.configureLdapAuthentication(auth);
        }
    }
}
