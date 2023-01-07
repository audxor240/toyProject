package com.toyProject.config.auth;

import com.toyProject.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Getter
public class PrincipalDetail implements UserDetails {

    private User user;	//콤포지션

    public PrincipalDetail(User user) {
        this.user = user;
    }

    public int getId() {
        return user.getId();
    }

    public List<String> getRols(){
        return user.getRoles();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    //계정이 만료되지 않았는지 리턴한다. (true : 만료됨)
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    //계정이 잠겨있지 않았는지 리턴한다. (true : 잠기지 않음)
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    //비밀번호가 만료되지 않았는지 리턴한다.(true : 만료안됨)
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    //계정 활성화(사용가능)인지 리턴한다.(true : 활성화)
    @Override
    public boolean isEnabled() {
        return  true;
    }

    // 계정이 갖고있는 궈한 목록을 리턴한다.(권한이 여러개 있을 수 있어서 루프를 돌아야 하는데 우리는 한개만)
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collectors = new ArrayList<>();
        collectors.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return "ROLE_"+user.getRole();	//ROLE_ 는 규칙임(없으면 못읽어온다.)
            }
        });

        collectors.add(()->{
            return "ROLE_"+user.getRole();
        });

        return collectors;
    }
}
