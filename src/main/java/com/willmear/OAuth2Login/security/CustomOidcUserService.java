package com.willmear.OAuth2Login.security;

import com.willmear.OAuth2Login.model.Oauth2UserInfoDto;
import com.willmear.OAuth2Login.model.User;
import com.willmear.OAuth2Login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    @Autowired
    private final UserRepository userRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        log.trace("Load user {}", userRequest);
        OidcUser oidcUser = super.loadUser(userRequest);

        try {
            return processOidcUser(userRequest, oidcUser);
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OidcUser processOidcUser(OidcUserRequest userRequest, OidcUser oidcUser) {
        Oauth2UserInfoDto userInfoDto = Oauth2UserInfoDto
                .builder()
                .name(oidcUser.getAttributes().get("name").toString())
                .id(oidcUser.getAttributes().get("sub").toString())
                .email(oidcUser.getAttributes().get("email").toString())
                .picture(oidcUser.getAttributes().get("picture").toString())
                .build();

        log.trace("User info is {}", userInfoDto);
        Optional<User> userOptional = userRepository.findByEmail(userInfoDto.getEmail());
        log.trace("User is {}", userOptional);
        userOptional
                .map(existingUser -> updateExistingUser(existingUser, userInfoDto))
                .orElseGet(() -> registerNewUser(userRequest, userInfoDto));
        return oidcUser;
    }

    private User registerNewUser(OidcUserRequest userRequest, Oauth2UserInfoDto userInfoDto) {
        User user = new User();
        user.setGoogleId(userInfoDto.getId());
        user.setName(userInfoDto.getName());
        user.setEmail(userInfoDto.getEmail());
        user.setProfileImageUrl(userInfoDto.getPicture());
        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, Oauth2UserInfoDto userInfoDto) {
        existingUser.setName(userInfoDto.getName());
        existingUser.setProfileImageUrl(userInfoDto.getPicture());
        return userRepository.save(existingUser);
    }
}
