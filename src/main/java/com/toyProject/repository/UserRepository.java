package com.toyProject.repository;

import com.toyProject.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);	//findBy+where절에 나오는 컬럼(첫글자는 대문자로),추가하려면 and+where절에 나오는 컬럼

    Optional<User> findByEmail(String email);

    //Optional<User> findByUserEmail(String email);
}
