package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;

    private final SecretKey secretKey;

    private final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService,
                                     SecretKey secretKey,
                                     JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
            .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
            .authorizeRequests()
            .antMatchers("/", "index", "css/*", "js/*").permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name())

            //Replaced these with @PreAuthorize annotation
            /*.antMatchers(HttpMethod.DELETE,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
            .antMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.name())
            .antMatchers(HttpMethod.PUT,"management/api/**").hasAuthority(COURSE_WRITE.name())
            .antMatchers(HttpMethod.GET,"management/api/**").hasAnyRole(ADMIN.name(),SUPERADMIN.name())
            */
            .anyRequest()
            .authenticated();
//            .httpBasic(); // basic authentication

            //form based authentication
            /*.formLogin()
                .loginPage("/login")
                .permitAll()
                .defaultSuccessUrl("/courses", true)
                .passwordParameter("password")
                .usernameParameter("username")
            .and()
            .rememberMe()
                .rememberMeParameter("remember-me")
            .and()
            .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "rememberMe")
                .logoutSuccessUrl("/login");*/
    }

    //Replaced this method and user details with userDao
  /*  @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails testUser = User.builder()
            .username("test")
            .password(passwordEncoder.encode("password"))
//            .roles(STUDENT.name()) //ROLE_STUDENT
            .authorities(STUDENT.getGrantedAuthorities())
            .build();

        UserDetails adminUser = User.builder()
            .username("admin")
            .password(passwordEncoder.encode("password123"))
//            .roles(ADMIN.name()) //ROLE_ADMIN
            .authorities(ADMIN.getGrantedAuthorities())
            .build();

        UserDetails superAdminUser = User.builder()
            .username("superAdmin")
            .password(passwordEncoder.encode("password123"))
//            .roles(SUPERADMIN.name()) //ROLE_SUPER_ADMIN
            .authorities(SUPERADMIN.getGrantedAuthorities())
            .build();

        return new InMemoryUserDetailsManager(
            testUser,adminUser,superAdminUser
        );
    }*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
