package com.ohgiraffers.security.auth.filter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ohgiraffers.security.auth.model.dto.LoginDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        super.setAuthenticationManager(authenticationManager);
    }

    // 지정된 url 요청시 해당 요청을 가로채서 검증 로직을 수행하는 메소드
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authenticationToken;

        try {
            authenticationToken = getAuthRequest(request);
            setDetails(request, authenticationToken);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return this.getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 사용자의 로그인 리소스 오청시 요청 정보를 임시 토큰에 저장하는 메소드
     *
     * @Param request = httpServletRequest
     * @return userPasswordAuthenticationToken
     * @throw Exception e
     * */
    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        objectMapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true); // simpleJson에서 Json형식의 요청을 알아서 파싱하도록 설정
        LoginDTO user = objectMapper.readValue(request.getInputStream(), LoginDTO.class); // 요청을 LoginDTO로 반환하기 위한 것

        return new UsernamePasswordAuthenticationToken(user.getId(), user.getPass());
    }
}
