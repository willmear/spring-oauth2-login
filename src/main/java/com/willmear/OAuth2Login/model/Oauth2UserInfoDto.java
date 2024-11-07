package com.willmear.OAuth2Login.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Oauth2UserInfoDto {

    private String name;
    private String id;
    private String email;
    private String picture;


}
