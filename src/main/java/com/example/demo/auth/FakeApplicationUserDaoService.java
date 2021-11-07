package com.example.demo.auth;

import com.example.demo.security.ApplicationUserPermission;
import com.example.demo.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(
                "test",
                passwordEncoder.encode("password"),
                ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                true,
                true,
                true,
                true
            ),
            new ApplicationUser(
                "admin",
                passwordEncoder.encode("password"),
                ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true
            ),new ApplicationUser(
                "superAdmin",
                passwordEncoder.encode("password"),
                ApplicationUserRole.SUPERADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true
            )
        );
        return applicationUsers;
    }
}
