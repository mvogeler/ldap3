package com.example.ldap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.ldap.OperationNotSupportedException;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.ArrayList;
import java.util.List;

@Service
public class LdapService {

    @Value("${ldap.url}")
    private String ldapUrl;

    @Value("${ldap.base.dn}")
    private String ldapBaseDn;

    @Value("${ldap.username}")
    private String ldapSecurityPrincipal;

    @Value("${ldap.password}")
    private String ldapPrincipalPassword;

    @Value("${ldap.user.dn.pattern}")
    private String ldapDnPattern;

    public List<GrantedAuthority> getRoles(String username) {
        LdapQuery groupQuery = LdapQueryBuilder.query().base(ldapBaseDn)
                .where("objectclass").is("groupOfUniqueNames");

        List<Group> groupList = getLdapTemplate().search(groupQuery, new GroupAttributesMapper());

        System.out.println(username);
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (Group group : groupList) {
            if (group.getUniqueMembers().contains("uid=" + username + "," + ldapBaseDn)) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + group.getName().toUpperCase()));
                System.out.println(group.getName());
            }
        }


        return authorities;
    }

    public void authenticateUser(String username, String password) {
        LdapQuery query = LdapQueryBuilder.query()
                .base(ldapBaseDn)
                .where("objectclass").is("inetOrgPerson")
                .and("uid").is(username);

        LdapTemplate ldapTemplate = getLdapTemplate();

        try {
            ldapTemplate.authenticate(query, password);
        } catch (EmptyResultDataAccessException e) {
            throw new UsernameNotFoundException("User '" + username + "' does not exist!");
        } catch (org.springframework.ldap.AuthenticationException e) {
            throw new BadCredentialsException("Invalid Username/Password Combination!");
        } catch (OperationNotSupportedException e) {
            throw new InsufficientAuthenticationException("Password Required!");
        }
    }

    public void configureLdapAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication()
                .contextSource()
                .url(ldapUrl + ldapBaseDn)
                .managerDn(ldapSecurityPrincipal)
                .managerPassword(ldapPrincipalPassword)
                .and()
                .userDnPatterns(ldapDnPattern);
    }

    private class GroupAttributesMapper implements AttributesMapper {

        @Override
        public Object mapFromAttributes(Attributes attributes) throws NamingException {
            Group group = new Group();
            group.setName((String) attributes.get("cn").get());

            NamingEnumeration attr = attributes.get("uniqueMember").getAll();
            while (attr.hasMore()) {
                String member = (String) attr.next();
                group.addUniqueMember(member);
            }

            return group;
        }
    }

    private LdapTemplate getLdapTemplate() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setUserDn(ldapSecurityPrincipal);
        contextSource.setPassword(ldapPrincipalPassword);
        try {
            contextSource.afterPropertiesSet();
        } catch (Exception e) {
            e.printStackTrace();
        }
        LdapTemplate ldapTemplate = new LdapTemplate();
        ldapTemplate.setContextSource(contextSource);
        return ldapTemplate;
    }
}
