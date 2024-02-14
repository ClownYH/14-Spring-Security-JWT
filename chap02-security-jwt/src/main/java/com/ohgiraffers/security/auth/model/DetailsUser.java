package com.ohgiraffers.security.auth.model;

import com.ohgiraffers.security.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailsUser implements UserDetails { // DB에서 가져온 데이터를 시큐리티에 맞는 타입으로 바뀜

    private User user;

    public DetailsUser(){

    }

    public DetailsUser(Optional<User> user) { // Optional의 객체에서 꺼내올 때는 get으로
        this.user = user.get();
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(() -> role));

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    // 아래 있는 것들은 DB에서도 관리를 해줘야 가능하다.

    /**
     * 계정 만료 여부를 표현하는 메서드
     * */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 계정이 잠겨있는지 확인하는 메서드
     * false이면 해당 계정을 사용할 수 없다.
     * 비밀번호 반복 실패로 일시적인 계정 lock의 경우
     * 혹은 오랜 기간 비 접속으로 휴면 처리
     * */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 탈퇴 계정 여부를 표현하는 메소드
     * false면 해당 계정을 사용할 수 없다.
     * */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 계정 비활성화 여부로 사용자가 사용할 수 없는 상태
     * false이면 계정을 사용할 수 없다.
     *
     * 삭제 처리 같은 경우
     * */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
