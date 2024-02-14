package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.common.AuthConstant;
import com.ohgiraffers.security.common.utils.ConvertUtil;
import com.ohgiraffers.security.common.utils.TokenUtils;
import com.ohgiraffers.security.user.entity.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = ((DetailsUser) authentication.getPrincipal()).getUser();
        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectToJsonObject(user);
        HashMap<String, Object> responseMap = new HashMap<>();
        JSONObject jsonObject;

        if(user.getState().equals("N")){
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "휴면 상태인 계정입니다.");
        }else {
            String token = TokenUtils.generateJwtToken(user); // 토큰 생성 로직
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "로그인 성공");

            response.addHeader(AuthConstant.AUTH_HEADER, AuthConstant.TOKEN_TYPE + " " + token); // 응답 헤더 설정
        }

        jsonObject = new JSONObject(responseMap);
        response.setCharacterEncoding("UTF-8"); // Spring 3.2 버전 이후로는 굳이 안해줘도 된다고 함
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();
        printWriter.println(jsonObject);
        printWriter.flush(); // 값을 내보냄
        printWriter.close(); // 리소스를 닫아줌
    }
}
