package com.example.ldap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private LdapService ldapService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println(username);
        String name = "";
        try {
            name = LdapUtils.getStringValue(new LdapName(username), "cn");

            //TODO check rest of DN?  Like O, C, OU?
            System.out.println(name);

        } catch (InvalidNameException e) {
            e.printStackTrace();
        }

        User result = new User(
                username, "",
                ldapService.getRoles(name));

        return result;
    }
}
