package com.toyProject.service;

import com.toyProject.dto.UserDto;
import com.toyProject.model.RoleType;
import com.toyProject.model.User;
import com.toyProject.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
@org.springframework.transaction.annotation.Transactional(readOnly = true)
public class UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final UserRepository userRepository;

    @Transactional
    public void createUser(UserDto.Save dto){
        System.out.println("createUser ::: "+dto);
        User user = User.builder()
                .username(dto.getUserId())
                .password(bCryptPasswordEncoder.encode(dto.getPassword()))
                .email(dto.getEmail())
                .oauth(dto.getOauth())
                .role(RoleType.USER)
                .roles(Collections.singletonList("ROLE_USER"))
                .build();

        userRepository.save(user);
    }

    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public User getUser(String username) {
        User user = userRepository.findByUsername(username).orElseGet(()->{
            return new User();	//빈 객체 전달
        });
        return user;
    }

    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public User getUserAsEmail(String email) {
        User user = userRepository.findByEmail(email).orElseGet(()->{
            return new User();	//빈 객체 전달
        });
        return user;
    }


}
