package com.jigsso.idsync;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.models.RealmModel;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 최소한의 Event Listener (등록 확인용 POC)
 */
public class MinimalEventListener implements EventListenerProvider {

    private final KeycloakSession session;

    public MinimalEventListener(KeycloakSession session) {
        this.session = session;
        System.out.println("POC: MinimalEventListener instance created!");
    }

    @Override
    public void onEvent(Event event) {
        // 모든 이벤트에 대해 간단한 로그만 출력 (요구사항 4.3)
        System.out.println("POC: Event received - Type: " + event.getType() +
                ", Realm: " + event.getRealmId() +
                ", User: " + event.getUserId());

        // // IDENTITY_PROVIDER_LOGIN, IDENTITY_PROVIDER_FIRST_LOGIN, LOGIN 이벤트 감지 (요구사항
        // // 1.1)
        // if (event.getType() == EventType.IDENTITY_PROVIDER_LOGIN ||
        //         event.getType() == EventType.IDENTITY_PROVIDER_FIRST_LOGIN ||
        //         event.getType() == EventType.LOGIN) {

        //     System.out.println("POC: " + event.getType() + " event detected");

        //     // Google Identity Provider 로그인 여부 확인 (또는 Google 사용자인지 확인)
        //     if (isGoogleLogin(event) || isGoogleUser(event)) {
        //         System.out.println("POC: Google login detected! User: " + event.getUserId());

        //         // Google Access Token 추출 시도 (요구사항 5.1)
        //         String accessToken = extractGoogleAccessToken(event);
        //         if (accessToken != null) {
        //             System.out.println("POC: Google Access Token extracted successfully");
        //             // 디버깅용 토큰 로그 출력 (일부만 표시)
        //             String tokenPreview = accessToken.length() > 20 ? accessToken.substring(0, 20) + "..."
        //                     : accessToken;
        //             System.out.println("POC: Token preview: " + tokenPreview);
        //         } else {
        //             System.out.println("POC: Failed to extract Google Access Token");
        //         }
        //     } else {
        //         System.out.println("POC: Non-Google identity provider login");
        //     }
        // }

        if (event.getType() == EventType.LOGIN) {
            String userId = event.getUserId();
            String realmId = event.getRealmId();

            System.out.println("POC: LOGIN event triggered");
            System.out.println("POC: userId = " + userId);
            System.out.println("POC: realmId = " + realmId);

            RealmModel realm = session.realms().getRealm(realmId);
            UserModel user = session.users().getUserById(realm, userId);

            if (user == null) {
                System.out.println("POC: Failed to retrieve user by userId!");
                return;
            }

            System.out.println("POC: User retrieved - username = " + user.getUsername());

            // 연결된 federated identity 가져오기
            Stream<FederatedIdentityModel> federatedIdentitiesStream =
                session.users().getFederatedIdentitiesStream(realm, user);
            List<FederatedIdentityModel> federatedIdentities =
                federatedIdentitiesStream.collect(Collectors.toList());

            System.out.println("POC: Federated identities found = " + federatedIdentities.size());

            for (FederatedIdentityModel identity : federatedIdentities) {
                String provider = identity.getIdentityProvider();
                String federatedUserId = identity.getUserId();

                System.out.println("POC: Found federated provider = " + provider);
                System.out.println("POC: Federated userId = " + federatedUserId);

                if (provider.equals("google")) {
                    String token = identity.getToken();  // access_token 저장된 곳

                    if (token != null && !token.isBlank()) {
                        System.out.println("POC: Google access token found, calling external API...");
                        // callGooglePeopleApi(token);  // 사용자 정보 추가 가져오기
                    } else {
                        System.out.println("POC: Google token is null or blank");
                    }
                }
            }
        }
    }

    /**
     * Google Identity Provider를 통한 로그인인지 확인
     * 
     * @param event LOGIN 이벤트
     * @return Google 로그인이면 true, 아니면 false
     */
    // private boolean isGoogleLogin(Event event) {
    //     // 이벤트 세부 정보에서 Identity Provider 정보 확인
    //     if (event.getDetails() != null) {
    //         String identityProvider = event.getDetails().get("identity_provider");
    //         if (identityProvider != null) {
    //             System.out.println("POC: Identity Provider detected: " + identityProvider);
    //             return "google".equals(identityProvider);
    //         }
    //     }

    //     // Identity Provider 정보가 없으면 일반 로그인으로 간주
    //     System.out.println("POC: No identity provider found, assuming direct login");
    //     return false;
    // }

    /**
     * 사용자가 Google Identity Provider를 통해 생성된 사용자인지 확인
     * LOGIN 이벤트에서 사용 (이벤트 세부 정보에 identity_provider가 없을 수 있음)
     * 
     * @param event LOGIN 이벤트
     * @return Google 사용자이면 true, 아니면 false
     */
    // private boolean isGoogleUser(Event event) {
    //     if (event.getUserId() == null) {
    //         return false;
    //     }

    //     try {
    //         UserModel user = session.users().getUserById(session.getContext().getRealm(), event.getUserId());
    //         if (user != null) {
    //             // 사용자의 FederatedIdentity에서 Google 연결 확인
    //             FederatedIdentityModel federatedIdentity = session.users()
    //                     .getFederatedIdentity(session.getContext().getRealm(), user, "google");

    //             if (federatedIdentity != null) {
    //                 System.out.println("POC: User has Google federated identity");
    //                 return true;
    //             }
    //         }
    //     } catch (Exception e) {
    //         System.out.println("POC: Exception while checking Google user: " + e.getMessage());
    //     }

    //     return false;
    // }

    /**
     * Keycloak 세션에서 Google Access Token을 추출
     * 
     * @param event IDENTITY_PROVIDER_LOGIN 또는 IDENTITY_PROVIDER_FIRST_LOGIN 이벤트
     * @return Google Access Token 또는 null (실패 시)
     */
    // private String extractGoogleAccessToken(Event event) {
    //     try {
    //         System.out.println("POC: Attempting to extract Google Access Token...");

    //         // 먼저 이벤트 세부 정보에서 토큰 조회 시도 (FIRST_LOGIN에서 유용)
    //         if (event.getDetails() != null) {
    //             System.out.println("POC: Checking event details for access token...");

    //             // 다양한 토큰 키 시도
    //             String[] tokenKeys = { "access_token", "google_access_token", "broker_access_token" };
    //             for (String key : tokenKeys) {
    //                 String token = event.getDetails().get(key);
    //                 if (token != null) {
    //                     System.out.println("POC: Access token found in event details with key: " + key);
    //                     return token;
    //                 }
    //             }

    //             // 이벤트 세부 정보 전체 출력 (디버깅용)
    //             System.out.println("POC: Event details keys: " + event.getDetails().keySet());
    //         }

    //         // 사용자 ID가 있는 경우 사용자 세션에서 토큰 조회
    //         if (event.getUserId() != null) {
    //             System.out.println("POC: User ID available, checking user session...");

    //             // 현재 사용자 세션 조회
    //             UserModel user = session.users().getUserById(session.getContext().getRealm(), event.getUserId());
    //             if (user == null) {
    //                 System.out.println("POC: User not found: " + event.getUserId());
    //             } else {
    //                 // 사용자 세션에서 브로커 세션 정보 조회
    //                 String sessionId = event.getSessionId();
    //                 if (sessionId != null) {
    //                     UserSessionModel userSession = session.sessions().getUserSession(
    //                             session.getContext().getRealm(),
    //                             sessionId);
    //                     if (userSession != null) {
    //                         System.out.println("POC: User session found, checking for broker token...");

    //                         // 브로커 토큰은 세션 노트에 저장될 수 있음
    //                         String brokerToken = userSession.getNote("BROKER_ACCESS_TOKEN");
    //                         if (brokerToken != null) {
    //                             System.out.println("POC: Broker access token found in session notes");
    //                             return brokerToken;
    //                         }

    //                         // Google 특정 토큰 키 시도
    //                         String googleToken = userSession.getNote("google.access_token");
    //                         if (googleToken != null) {
    //                             System.out.println("POC: Google access token found in session notes");
    //                             return googleToken;
    //                         }

    //                         System.out.println("POC: No access token found in session notes");
    //                     } else {
    //                         System.out.println("POC: User session not found for session ID: " + sessionId);
    //                     }
    //                 } else {
    //                     System.out.println("POC: No session ID in event");
    //                 }
    //             }
    //         } else {
    //             System.out.println("POC: No user ID in event (normal for FIRST_LOGIN), trying alternative methods...");

    //             // code_id를 사용해서 인증 세션에서 토큰 조회 시도
    //             if (event.getDetails() != null) {
    //                 String codeId = event.getDetails().get("code_id");
    //                 if (codeId != null) {
    //                     System.out.println("POC: Found code_id, checking authentication session: " + codeId);

    //                     try {
    //                         // Root Authentication Session에서 Authentication Session 조회
    //                         RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions()
    //                                 .getRootAuthenticationSession(session.getContext().getRealm(), codeId);

    //                         if (rootAuthSession != null) {
    //                             System.out.println("POC: Root authentication session found");

    //                             // 클라이언트별 Authentication Session 조회
    //                             for (String clientId : rootAuthSession.getAuthenticationSessions().keySet()) {
    //                                 AuthenticationSessionModel authSession = rootAuthSession.getAuthenticationSessions()
    //                                         .get(clientId);
    //                                 if (authSession != null) {
    //                                     System.out.println("POC: Checking auth session for client: " + clientId);

    //                                     // 인증 세션 노트에서 브로커 토큰 조회
    //                                     String[] brokerTokenKeys = {
    //                                             "BROKER_ACCESS_TOKEN",
    //                                             "google.access_token",
    //                                             "IDENTITY_PROVIDER_ACCESS_TOKEN",
    //                                             "access_token"
    //                                     };

    //                                     for (String tokenKey : brokerTokenKeys) {
    //                                         String token = authSession.getAuthNote(tokenKey);
    //                                         if (token != null) {
    //                                             System.out.println("POC: Access token found in auth session with key: "
    //                                                     + tokenKey);
    //                                             return token;
    //                                         }
    //                                     }

    //                                     // 사용자 세션 노트도 확인
    //                                     for (String tokenKey : brokerTokenKeys) {
    //                                         String token = authSession.getUserSessionNotes().get(tokenKey);
    //                                         if (token != null) {
    //                                             System.out.println(
    //                                                     "POC: Access token found in user session notes with key: "
    //                                                             + tokenKey);
    //                                             return token;
    //                                         }
    //                                     }

    //                                     System.out.println(
    //                                             "POC: No access token found in auth session for client: " + clientId);
    //                                 }
    //                             }
    //                         } else {
    //                             System.out.println("POC: Root authentication session not found for code_id: " + codeId);
    //                         }
    //                     } catch (Exception authEx) {
    //                         System.out.println(
    //                                 "POC: Exception while checking authentication session: " + authEx.getMessage());
    //                         authEx.printStackTrace();
    //                     }
    //                 } else {
    //                     System.out.println("POC: No code_id found in event details");
    //                 }
    //             }
    //         }

    //         // 토큰을 찾을 수 없는 경우 (요구사항 5.4)
    //         System.out.println("POC: Google Access Token not found in any location");
    //         return null;

    //     } catch (Exception e) {
    //         // 예외 발생 시 로깅 및 null 반환 (요구사항 5.2)
    //         System.out.println("POC: Exception while extracting Google Access Token: " + e.getMessage());
    //         e.printStackTrace();
    //         return null;
    //     }
    // }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin 이벤트는 무시
    }

    @Override
    public void close() {
        System.out.println("POC: MinimalEventListener closed");
    }
}