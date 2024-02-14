package com.ohgiraffers.security.common.utils;

import com.ohgiraffers.security.user.entity.User;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenUtils {

    private static String jwtSecretKey;

    private static Long tokenValidateTime;

    @Value("${jwt.key}")
    public static void setJwtSecretKey(String jwtSecretKey) {
        TokenUtils.jwtSecretKey = jwtSecretKey;
    }

    @Value("${jwt.time}")
    public static void setTokenValidateTime(Long tokenValidateTime) {
        TokenUtils.tokenValidateTime = tokenValidateTime;
    }

    /**
     * header의 token을 분리하는 메소드
     * @Param header : Authorization의 header값을 가져온다.
     * @return token : Authorization의 token을 반환한다.
     * */
    public static String splitHeader(String header){
        if(!header.equals("")){
            return header.split(" ")[1];
        }else {
            return null;
        }
    }

    /**
     * 유효한 토큰인지 확인하는 메소드
     * @Param token : 토큰
     * @return boolean : 유효 여부
     * @throws ExpiredJwtException, {@link io.jsonwebtoken.JwtException} {@link NullPointerException}
     * */
    public static boolean isValidToken(String token){

        try{
            Claims claims = getClaimsFormToken(token); // body = payload = claim은 같은 말로 쓰이고, 복호화가 안된다는 것은 유효하지 않다는 의미이다.
            return true;
        }catch (ExpiredJwtException e){
            e.printStackTrace();
            return false;
        }catch (JwtException e){
            e.printStackTrace();
            return false;
        }catch (NullPointerException e){
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 토큰을 복호화하는 메소드
     * @Param token
     * @return Claims
     * */
    public static Claims getClaimsFormToken(String token){
        return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretKey))
                .parseClaimsJws(token).getBody();
    }

    /**
     * token을 생성하는 메소드
     * @Param user userEntity
     * @return String token
     * */
    public static String generateJwtToken(User user){

        Date expireTime = new Date(System.currentTimeMillis()+tokenValidateTime);

        JwtBuilder builder = Jwts.builder() // 토큰 생성을 위해 제공되는 lib
                .setHeader(createHeader())
                .setClaims(createClaims(user))
                .setSubject("ohgiraffers token : " + user.getUserNo())
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(expireTime);

        return builder.compact(); // 토큰이 생성
    }

    /**
     * token의 header를 설정하는 부분이다.
     * @return Map<String, Object> header의 설정 정보
     * */
    private static Map<String, Object> createHeader(){
        Map<String, Object> header = new HashMap<>();

        header.put("type", "jwt");
        header.put("alg", "HS256");
        header.put("date", System.currentTimeMillis());

        return header;
    }

    /**
     * 사용자 정보를 기반으로 클레임을 생성해주는 메소드
     * @Param user 사용자 정보
     * @return Map<String, Object> = claims 정보
     * */
    private static Map<String, Object> createClaims(User user){
        Map<String, Object> claims = new HashMap<>();
        claims.put("userName", user.getUserName());
        claims.put("Role", user.getRole());
        claims.put("userEmail", user.getUserEmail());

        return claims;
    }

    /**
     * Jwt 서명을 발급해주는 메소드이다.
     * @return key
     * */
    private static Key createSignature(){
        byte[] secretBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey); // 2진 데이터(바이너리 데이터)로 변환
        return new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName()); // HS256 체계로 암호화(Key)
    }
}
