package com.karthik.test.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import com.karthik.test.auth.ApplicationUserService;
import com.karthik.test.jwt.JwtConfig;
import com.karthik.test.jwt.JwtTokenVerifier;
import com.karthik.test.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import static com.karthik.test.security.ApplicationUserRole.*;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import static com.karthik.test.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{

	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, JwtConfig jwtConfig, SecretKey secretKey) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//For Basic Auth and Form Based Validation
//		http
//			.csrf().disable()
////			.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////			.and()
//			.authorizeRequests()
//			.antMatchers("/","index","/java","/spring").permitAll()
//			.antMatchers("/api/**").hasRole(STUDENT.name())
//			//below antMatchers are not needed if we use @PreAuthorize and @EnableGlobalMethodSecurity(prePostEnabled = true)
////			.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////			.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////			.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
////			.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name() , ADMINTRAINEE.name())
//			.anyRequest()
//			.authenticated()
//			.and()
////			.httpBasic(); //Basic Auth
//			.formLogin() //Form Based Validation
//				.loginPage("/login")
//				.permitAll()
//				.defaultSuccessUrl("/courses",true)
////			.and()
////			.rememberMe() // Default Cookie deletion duration is 2 weeks
////			.rememberMe()
////				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)); // Cookie deletion duration changed to 21 Days
////				.key("somethingverysecured");
////				.rememberMeParameter("remember-me");
//			.and()
//			.logout()
//				.logoutUrl("/logout")
//				.clearAuthentication(true)
//				.invalidateHttpSession(true)
//				.deleteCookies("JSESSIONID")
//				.logoutSuccessUrl("/login");
		
		//For JWT
		http
			.csrf().disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
			.addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/","index","/java","/spring").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()
			.authenticated();
	}

//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		UserDetails student = User.builder()
//									.username("student")
//									.password(passwordEncoder.encode("pass"))
////									.roles(STUDENT.name())
//									.authorities(STUDENT.getGrantedAuthorities())
//									.build();
//		UserDetails admin = User.builder()
//									.username("admin")
//									.password(passwordEncoder.encode("pass"))
////									.roles(ADMIN.name())
//									.authorities(ADMIN.getGrantedAuthorities())
//									.build();
//		UserDetails admintrainee = User.builder()
//									.username("admintrainee")
//									.password(passwordEncoder.encode("pass"))
////									.roles(ADMINTRAINEE.name())
//									.authorities(ADMINTRAINEE.getGrantedAuthorities())
//									.build();
//		return new InMemoryUserDetailsManager( student , admin , admintrainee );
//	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
		
		//For Jdbc Authentication
		//auth.jdbcAuthentication().dataSource(dataSource);
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}
	

	
}
