package com.karthik.test.auth;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import com.google.common.collect.Lists;
import static com.karthik.test.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

	private PasswordEncoder passwordEncoder;

	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers().stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser("student",passwordEncoder.encode("pass"),STUDENT.getGrantedAuthorities(),true,true,true,true),
				new ApplicationUser("admin",passwordEncoder.encode("pass"),ADMIN.getGrantedAuthorities(),true,true,true,true),
				new ApplicationUser("admintrainee",passwordEncoder.encode("pass"),ADMINTRAINEE.getGrantedAuthorities(),true,true,true,true)							
				);
		return applicationUsers;
	}

	
}
