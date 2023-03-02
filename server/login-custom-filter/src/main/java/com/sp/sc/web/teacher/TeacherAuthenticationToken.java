package com.sp.sc.web.teacher;

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
public class TeacherAuthenticationToken implements Authentication {

    private Teacher principal;  // principal 오버라이딩 대신 롬복으로 자동 getter 생성하게 함
    private String credentials;  // credentials 오버라이딩 대신 롬복으로 자동 getter 생성하게 함
    private String details;  // details 오버라이딩 대신 롬복으로 자동 getter 생성하게 함
    private boolean authenticated;  // 통행증에 도장을 찍을 장소. 오버라이딩 대신 롬복으로 자동 getter 생성하게 함

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return principal == null ? new HashSet<>() : principal.getRole();
    }

    @Override
    public String getName() {
        return principal == null ? "" : principal.getUsername();
    }
}
