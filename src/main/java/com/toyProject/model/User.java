package com.toyProject.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.sql.Timestamp;
import java.util.Collection;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
//ORM -> JAVA(다르언어) Object -> 테이블로 매핑해주는 기술
@Entity    //User 클래스가 자동으로 Mysql에 테이블이 생성된다.
//@DynamicInsert		// insert시에 null인 필드를 제외시켜준다.
public class User {

    @Id    //Primary Key
    @GeneratedValue(strategy = GenerationType.IDENTITY)		// 프로젝트에서 연결된 DB의 넘버링 전략을 따라간다.
    private int id; //시퀀스, auto-increment

    @Column(nullable = false, length = 100, unique = true)		//중복안됨
    private String username; // 아이디

    @Column(nullable = false, length = 100)
    private String password;

    @Column(nullable = false, length = 50)
    private String email;

    //@ColumnDefault("'user'")
    // DB는 RoleType이라는게 없다.
    @Enumerated(EnumType.STRING)
    private RoleType role;	//Enum을 쓰는게 좋다.	//ADMIN, UER

    private String oauth;	//kakao, google

    @CreationTimestamp    // 시간이 자동 입력
    private Timestamp createDate;

    private Collection<? extends GrantedAuthority> authorities;
}
