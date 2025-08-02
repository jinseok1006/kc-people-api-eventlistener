package com.jigsso.googlesync;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.RealmModel;

import java.util.stream.Stream;
import java.io.IOException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 전북대학교 구글 프로필 동기화 이벤트 리스너
 * 
 * JBNU 사용자가 구글 계정으로 로그인할 때 Google People API를 통해
 * 사용자의 조직 정보(외부 ID, 부서)를 자동으로 Keycloak 프로필에 동기화합니다.
 */
public class JbnuGoogleProfileSyncEventListener implements EventListenerProvider {

    private static final Logger logger = Logger.getLogger(JbnuGoogleProfileSyncEventListener.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String GOOGLE_PEOPLE_API_URL = "https://people.googleapis.com/v1/people/me?personFields=organizations,externalIds";
    private static final String GOOGLE_PROVIDER_ID = "google";

    private final KeycloakSession session;

    public JbnuGoogleProfileSyncEventListener(KeycloakSession session) {
        this.session = session;
        logger.info("전북대 구글 프로필 동기화 이벤트 리스너가 생성되었습니다.");
    }

    @Override
    public void onEvent(Event event) {
        // 모든 이벤트에 대해 간단한 로그만 출력 (요구사항 4.3)
        logger.debug("이벤트 수신 - 타입: " + event.getType() + 
                ", 영역: " + event.getRealmId() + ", 사용자: " + event.getUserId());

        if (event.getType() == EventType.LOGIN) {
            handleLoginEvent(event);
        }
    }

    private void handleLoginEvent(Event event) {
        String userId = event.getUserId();
        String realmId = event.getRealmId();

        if (userId == null || realmId == null) {
            logger.warn("로그인 이벤트에 null 데이터 포함 - 사용자ID: " + userId + ", 영역ID: " + realmId);
            return;
        }

        logger.info("로그인 이벤트 감지됨");
        logger.info("사용자ID: " + userId);
        logger.info("영역ID: " + realmId);

        RealmModel realm = session.realms().getRealm(realmId);
        if (realm == null) {
            logger.warn("영역을 찾을 수 없음 - ID: " + realmId);
            return;
        }

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            logger.warn("사용자를 찾을 수 없음 - 사용자ID: " + userId + ", 영역: " + realmId);
            return;
        }

        logger.debug("사용자 조회 완료 - 사용자명: " + user.getUsername());

        // Google Identity 처리 - Stream을 직접 사용하여 성능 최적화
        session.users().getFederatedIdentitiesStream(realm, user)
            .filter(identity -> GOOGLE_PROVIDER_ID.equals(identity.getIdentityProvider()))
            .findFirst()
            .ifPresent(identity -> processGoogleIdentity(identity, user, realm));
    }

    private void processGoogleIdentity(FederatedIdentityModel identity, UserModel user, RealmModel realm) {
        if (identity == null) {
            logger.warn("연합 신원 모델이 null입니다");
            return;
        }

        String provider = identity.getIdentityProvider();
        String federatedUserId = identity.getUserId();

        if (provider == null || federatedUserId == null) {
            logger.warn("연합 신원에 null 데이터 포함 - 공급자: " + provider + ", 사용자ID: " + federatedUserId);
            return;
        }

        logger.debug("연합 공급자 발견: " + provider);
        logger.debug("연합 사용자ID: " + federatedUserId);

        String token = identity.getToken();
        if (token == null || token.isBlank()) {
            logger.debug("구글 토큰이 null이거나 비어있음");
            return;
        }

        logger.debug("구글 액세스 토큰 발견!");
        logger.debug("토큰 길이: " + token.length());
        logger.debug("전체 토큰 내용: " + token);
        
        analyzeTokenFormat(token);
        
        // 사용자가 @jbnu.ac.kr 이메일인지 확인
        if (!isJbnuUser(user)) {
            logger.debug("비 전북대 사용자, API 호출 생략");
            return;
        }

        logger.info("전북대 사용자 감지, 구글 People API 호출 시작: " + user.getUsername());
        
        // JSON에서 실제 access_token 추출
        String actualToken = extractAccessTokenFromJson(token);
        if (actualToken != null) {
            // Google People API 호출
            callGooglePeopleApi(actualToken, user.getUsername(), user, realm);
        } else {
            logger.warn("액세스 토큰 추출 실패: " + user.getUsername());
        }
    }

    private void analyzeTokenFormat(String token) {
        if (token == null) {
            logger.debug("토큰이 null이므로 형식 분석 불가");
            return;
        }

        // 토큰이 JWT인지 확인 (점으로 구분된 3개 부분)
        String[] tokenParts = token.split("\\.");
        logger.debug("토큰 구성 요소 개수: " + tokenParts.length);
        if (tokenParts.length == 3) {
            logger.debug("토큰이 JWT 형식으로 판단됨");
            logger.debug("헤더: " + tokenParts[0]);
            logger.debug("페이로드: " + tokenParts[1]);
            logger.debug("서명: " + tokenParts[2]);
        } else {
            logger.debug("토큰이 JWT 형식이 아님");
        }
    }

    private boolean isJbnuUser(UserModel user) {
        if (user == null) {
            logger.warn("전북대 사용자 확인 시 사용자가 null입니다");
            return false;
        }

        String userEmail = user.getEmail();
        return userEmail != null && !userEmail.trim().isEmpty() && userEmail.endsWith("@jbnu.ac.kr");
    }

    /**
     * JSON 형태의 토큰에서 실제 access_token 값을 추출
     */
    private String extractAccessTokenFromJson(String tokenString) {
        if (tokenString == null || tokenString.trim().isEmpty()) {
            logger.warn("토큰 문자열이 null이거나 비어있음");
            return null;
        }

        try {
            // JSON 형태인지 확인
            if (tokenString.trim().startsWith("{") && tokenString.trim().endsWith("}")) {
                logger.info("JSON 형태의 토큰 감지, access_token 추출 시도");

                // Jackson ObjectMapper를 사용한 JSON 파싱
                JsonNode jsonNode = OBJECT_MAPPER.readTree(tokenString);
                
                if (jsonNode.has("access_token")) {
                    String accessToken = jsonNode.get("access_token").asText();
                    if (accessToken != null && !accessToken.isEmpty()) {
                        logger.info("JSON에서 access_token 추출 성공: " + 
                                accessToken.substring(0, Math.min(10, accessToken.length())) + "...");
                        return accessToken;
                    } else {
                        logger.warn("access_token 필드가 null이거나 비어있음");
                    }
                } else {
                    logger.error("JSON에서 access_token 키를 찾을 수 없음");
                    logger.info("사용 가능한 키들: " + jsonNode.fieldNames().toString());
                }
            } else {
                // JSON이 아닌 경우 그대로 반환
                logger.info("JSON이 아닌 일반 토큰으로 판단, 그대로 사용");
                return tokenString;
            }
        } catch (Exception e) {
            logger.error("토큰 JSON 파싱 중 오류 발생", e);
        }

        return null;
    }

    private void callGooglePeopleApi(String accessToken, String username, UserModel user, RealmModel realm) {
        if (accessToken == null || accessToken.trim().isEmpty()) {
            logger.warn("액세스 토큰이 null이거나 비어있어 구글 People API 호출 불가");
            return;
        }

        if (username == null) {
            logger.warn("사용자명이 null이어서 구글 People API 호출 불가");
            return;
        }

        logger.info("=== 구글 People API 호출 시작 (SimpleHttp) ===");
        logger.info("사용자: " + username);
        logger.info("API URL: " + GOOGLE_PEOPLE_API_URL);
        logger.info("토큰 길이: " + accessToken.length());
        logger.info("토큰 시작: " + accessToken.substring(0, Math.min(30, accessToken.length())) + "...");

        try {
            JsonNode response = SimpleHttp.doGet(GOOGLE_PEOPLE_API_URL, session)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .header("User-Agent", "Keycloak-SPI/1.0")
                .asJson();

            if (response != null) {
                logger.info("=== API 호출 성공! ===");
                logger.info("응답 본문: " + response.toString());
                
                // 응답 데이터를 파싱하여 사용자 프로필 업데이트
                updateUserProfileFromJson(response, user);
            } else {
                logger.warn("API 응답이 null입니다");
            }

        } catch (IOException e) {
            logger.error("=== 구글 People API 호출 중 예외 발생 ===", e);
            logger.error("예외 타입: " + e.getClass().getSimpleName());
            logger.error("예외 메시지: " + e.getMessage());
        }

        logger.info("=== 구글 People API 호출 완료 ===");
    }

    /**
     * Google People API 응답(JsonNode)을 파싱하여 사용자 프로필 업데이트
     */
    private void updateUserProfileFromJson(JsonNode response, UserModel user) {
        if (response == null) {
            logger.warn("응답 JsonNode가 null이어서 사용자 프로필 업데이트 불가");
            return;
        }

        if (user == null) {
            logger.warn("사용자가 null이어서 사용자 프로필 업데이트 불가");
            return;
        }

        logger.info("=== 사용자 프로필 업데이트 시작 ===");

        try {
            // externalId 추출 및 업데이트
            if (response.has("externalIds")) {
                JsonNode externalIds = response.get("externalIds");
                if (externalIds.isArray() && externalIds.size() > 0) {
                    JsonNode firstExternalId = externalIds.get(0);
                    if (firstExternalId != null && firstExternalId.has("value")) {
                        String externalId = firstExternalId.get("value").asText();
                        if (externalId != null && !externalId.trim().isEmpty()) {
                            logger.info("외부 ID 추출 성공: " + externalId);
                            user.setSingleAttribute("externalId", externalId);
                            logger.info("사용자 프로필에 외부 ID 설정 완료");
                        } else {
                            logger.warn("외부 ID 값이 null이거나 비어있음");
                        }
                    }
                }
            } else {
                logger.warn("외부 ID를 찾을 수 없습니다");
            }

            // department 추출 및 업데이트
            if (response.has("organizations")) {
                JsonNode organizations = response.get("organizations");
                if (organizations.isArray() && organizations.size() > 0) {
                    JsonNode firstOrg = organizations.get(0);
                    if (firstOrg != null && firstOrg.has("department")) {
                        String department = firstOrg.get("department").asText();
                        if (department != null && !department.trim().isEmpty()) {
                            logger.info("부서 추출 성공: " + department);
                            user.setSingleAttribute("department", department);
                            logger.info("사용자 프로필에 부서 설정 완료");
                        } else {
                            logger.warn("부서 값이 null이거나 비어있음");
                        }
                    }
                }
            } else {
                logger.warn("조직 정보를 찾을 수 없습니다");
            }

            logger.info("=== 사용자 프로필 업데이트 완료 ===");

        } catch (Exception e) {
            logger.error("사용자 프로필 업데이트 중 오류 발생", e);
        }
    }


    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin 이벤트는 무시
    }

    @Override
    public void close() {
        logger.info("전북대 구글 프로필 동기화 이벤트 리스너가 종료되었습니다");
    }
}