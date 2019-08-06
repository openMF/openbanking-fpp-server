/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.controller;


import com.auth0.jwt.JWT;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Payload;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import hu.dpc.common.http.oauth2.OAuthAuthorizationRequiredException;
import hu.dpc.common.http.oauth2.TokenResponse;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.AccessToken;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.Authorities;
import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.Users;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.AuthoritiesRepository;
import hu.dpc.openbank.fpp.lionfintech.backend.repository.UsersRepository;
import hu.dpc.openbank.oauth2.TokenManager;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequestMapping(path = "/token/v1/")
public class TokenController extends WSO2Controller {
    private static final Logger LOG = LoggerFactory.getLogger(TokenController.class);

    @Autowired
    private UsersRepository       usersRepository;
    @Autowired
    private AuthoritiesRepository authoritiesRepository;


    @Transactional
    @GetMapping(path = "/code/{Code}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getTokenCodeForAccounts(@RequestHeader(X_TPP_BANKID) final String bankId,
                                                          @PathVariable("Code") final String code) {
        LOG.info("GET /token/v1/code/{}    bankId={}", code, bankId);
        return exchangeToken(bankId, code);
    }

    public ResponseEntity<String> exchangeToken(final String bankId, final String code) {
        final TokenManager  tokenManager        = getTokenManager(bankId);
        final TokenResponse accessTokenResponse = tokenManager.getAccessTokenFromCode(code);
        final int           responseCode        = accessTokenResponse.getHttpResponseCode();
        if (200 <= responseCode && 300 > responseCode) {
            // Extract username from id_token
            final DecodedJWT decodedJWT = JWT.decode(accessTokenResponse.getIdToken());
            final Payload payLoad = new JWTParser().parsePayload(new String(Base64.getDecoder()
                                                                                  .decode(decodedJWT.getPayload())));
            String                     userName    = payLoad.getSubject();
            final @NotNull AccessToken accessToken = createAndSaveUserAccessToken(accessTokenResponse, bankId, userName);

            // Create or update user account for reduce development while LionFintech derived from ACEFintech
            Users   user      = usersRepository.findByUserName(userName);
            boolean isNewUser = (null == user);
            if (isNewUser) {
                user = new Users();
                user.setUserName(userName);
            }
            PasswordEncoder encoder  = PasswordEncoderFactories.createDelegatingPasswordEncoder();
            String          password = encoder.encode(accessToken.getAccessToken());
            user.setPassword(password);
            user.setEnabled(true);
            usersRepository.saveAndFlush(user);

            if (isNewUser) {
                Authorities userAuthority = new Authorities();
                userAuthority.setUserName(userName);
                userAuthority.setAuthority("ROLE_USER");
                authoritiesRepository.saveAndFlush(userAuthority);
            }

            ObjectMapper mapper = new ObjectMapper();
            final String json;
            try {
                Users returnUser = new Users();
                returnUser.setUserName(userName);
                returnUser.setPassword(accessToken.getAccessToken());
                json = mapper.writeValueAsString(returnUser);
            } catch (JsonProcessingException e) {
                LOG.error("Object to JSON mapping error", e);
                throw new OAuthAuthorizationRequiredException("");
            }
            return new ResponseEntity(json, HttpStatus.OK);
        }
        LOG.warn("Code exchange not succeeded. HTTP[{}] RAWResponse [{}]", responseCode, accessTokenResponse
                .getHttpRawContent());
        LOG.info("No user AccessToken exists. OAuth authorization required!");
        throw new OAuthAuthorizationRequiredException("");
    }

}
