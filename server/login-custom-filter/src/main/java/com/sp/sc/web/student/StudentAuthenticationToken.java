package com.sp.sc.web.student;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StudentAuthenticationToken implements Authentication {

    private Student principal;  // principal 오버라이딩 대신 롬복으로 자동 getter 생성하게 함
    private String credentials;  // credentials 오버라이딩 대신 롬복으로 자동 getter 생성하게 함
    private String details;  // details 오버라이딩 대신 롬복으로 자동 getter 생성하게 함
    private boolean authenticated;  // 통행증에 도장을 찍을 장소. 오버라이딩 대신 롬복으로 자동 getter 생성하게 함

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return principal == null ? new HashSet<>() : principal.getRole();  // Student가 GrantedAuthority를 가지고 있기 때문에 없으면 빈 객체, 있으면 롤 가져오기
    }

    @Override
    public String getName() {
        return principal == null ? "" : principal.getUsername();
    }
}
