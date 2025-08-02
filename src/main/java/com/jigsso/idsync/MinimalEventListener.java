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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 최소한의 Event Listener (등록 확인용 POC)
 */
public class MinimalEventListener implements EventListenerProvider {

    private static final Logger logger = Logger.getLogger(MinimalEventListener.class);
    private static final String GOOGLE_PEOPLE_API_URL = "https://people.googleapis.com/v1/people/me?personFields=organizations,externalIds";
    private static final String GOOGLE_PROVIDER_ID = "google";

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
                        System.out.println("POC: Google access token found!");
                        System.out.println("POC: Token length: " + token.length());
                        System.out.println("POC: Full token content: " + token);
                        
                        // 토큰이 JWT인지 확인 (점으로 구분된 3개 부분)
                        String[] tokenParts = token.split("\\.");
                        System.out.println("POC: Token parts count: " + tokenParts.length);
                        if (tokenParts.length == 3) {
                            System.out.println("POC: Token appears to be JWT format");
                            System.out.println("POC: Header: " + tokenParts[0]);
                            System.out.println("POC: Payload: " + tokenParts[1]);
                            System.out.println("POC: Signature: " + tokenParts[2]);
                        } else {
                            System.out.println("POC: Token is not JWT format");
                        }
                        
                        // 사용자가 @jbnu.ac.kr 이메일인지 확인
                        String userEmail = user.getEmail();
                        if (userEmail != null && userEmail.endsWith("@jbnu.ac.kr")) {
                            logger.info("JBNU 사용자 감지, Google People API 호출 시작: " + user.getUsername());
                            
                            // JSON에서 실제 access_token 추출
                            String actualToken = extractAccessTokenFromJson(token);
                            if (actualToken != null) {
                                // Google People API 호출
                                callGooglePeopleApi(actualToken, user.getUsername(), user, realm);
                            } else {
                                logger.warn("액세스 토큰 추출 실패: " + user.getUsername());
                            }
                        } else {
                            System.out.println("POC: 비 JBNU 사용자, API 호출 생략");
                        }
                    } else {
                        System.out.println("POC: Google token is null or blank");
                    }
                }
            }
        }
    }

    /**
     * JSON 형태의 토큰에서 실제 access_token 값을 추출
     */
    private String extractAccessTokenFromJson(String tokenString) {
        try {
            // JSON 형태인지 확인
            if (tokenString.trim().startsWith("{") && tokenString.trim().endsWith("}")) {
                logger.info("JSON 형태의 토큰 감지, access_token 추출 시도");

                // 간단한 JSON 파싱 (Jackson 사용하지 않고 문자열 처리)
                String searchKey = "\"access_token\":\"";
                int startIndex = tokenString.indexOf(searchKey);

                if (startIndex != -1) {
                    startIndex += searchKey.length();
                    int endIndex = tokenString.indexOf("\"", startIndex);

                    if (endIndex != -1) {
                        String accessToken = tokenString.substring(startIndex, endIndex);
                        logger.info("JSON에서 access_token 추출 성공: "
                                + accessToken.substring(0, Math.min(10, accessToken.length())) + "...");
                        return accessToken;
                    } else {
                        logger.error("access_token 값의 끝을 찾을 수 없음");
                    }
                } else {
                    logger.error("JSON에서 access_token 키를 찾을 수 없음");
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
        logger.info("=== Google People API 호출 시작 ===");
        logger.info("사용자: " + username);
        logger.info("API URL: " + GOOGLE_PEOPLE_API_URL);
        logger.info("토큰 길이: " + accessToken.length());
        logger.info("토큰 시작: " + accessToken.substring(0, Math.min(30, accessToken.length())) + "...");

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(GOOGLE_PEOPLE_API_URL);
            request.setHeader("Authorization", "Bearer " + accessToken);
            request.setHeader("Accept", "application/json");
            request.setHeader("User-Agent", "Keycloak-SPI/1.0");

            logger.info("HTTP 요청 헤더 설정 완료");
            logger.info(
                    "Authorization: Bearer " + accessToken.substring(0, Math.min(20, accessToken.length())) + "...");

            logger.info("HTTP 요청 실행 중...");
            var response = httpClient.execute(request);

            int statusCode = response.getStatusLine().getStatusCode();
            String statusMessage = response.getStatusLine().getReasonPhrase();
            String responseBody = EntityUtils.toString(response.getEntity());

            logger.info("=== API 응답 상세 정보 ===");
            logger.info("상태 코드: " + statusCode);
            logger.info("상태 메시지: " + statusMessage);
            logger.info("응답 본문 길이: " + responseBody.length());
            logger.info("응답 본문: " + responseBody);

            // 응답 헤더도 출력
            logger.info("=== 응답 헤더 ===");
            for (var header : response.getAllHeaders()) {
                logger.info(header.getName() + ": " + header.getValue());
            }

            if (statusCode == 401) {
                logger.error("=== 401 Unauthorized 분석 ===");
                logger.error("토큰이 만료되었거나 유효하지 않을 수 있습니다");
                logger.error("토큰 전체 길이: " + accessToken.length());
                if (responseBody.contains("invalid_token")) {
                    logger.error("응답에 'invalid_token' 포함됨");
                }
                if (responseBody.contains("expired")) {
                    logger.error("응답에 'expired' 포함됨 - 토큰 만료");
                }
            } else if (statusCode == 200) {
                logger.info("=== API 호출 성공! ===");
                // 응답 데이터를 파싱하여 사용자 프로필 업데이트
                updateUserProfile(responseBody, user);
            }

        } catch (Exception e) {
            logger.error("=== Google People API 호출 중 예외 발생 ===", e);
            logger.error("예외 타입: " + e.getClass().getSimpleName());
            logger.error("예외 메시지: " + e.getMessage());
        }

        logger.info("=== Google People API 호출 완료 ===");
    }

    /**
     * Google People API 응답을 파싱하여 사용자 프로필 업데이트
     */
    private void updateUserProfile(String responseBody, UserModel user) {
        logger.info("=== 사용자 프로필 업데이트 시작 ===");

        try {
            // externalId 추출 및 업데이트
            String externalId = extractExternalId(responseBody);
            if (externalId != null && !externalId.trim().isEmpty()) {
                logger.info("External ID 추출 성공: " + externalId);
                user.setSingleAttribute("externalId", externalId);
                logger.info("사용자 프로필에 externalId 설정 완료");
            } else {
                logger.warn("External ID를 찾을 수 없습니다");
            }

            // department 추출 및 업데이트
            String department = extractDepartment(responseBody);
            if (department != null && !department.trim().isEmpty()) {
                logger.info("Department 추출 성공: " + department);
                user.setSingleAttribute("department", department);
                logger.info("사용자 프로필에 department 설정 완료");
            } else {
                logger.warn("Department를 찾을 수 없습니다");
            }

            logger.info("=== 사용자 프로필 업데이트 완료 ===");

        } catch (Exception e) {
            logger.error("사용자 프로필 업데이트 중 오류 발생", e);
        }
    }

    /**
     * JSON 응답에서 첫 번째 externalId 값 추출
     */
    private String extractExternalId(String responseBody) {
        try {
            logger.info("External ID 추출 시도 중...");
            
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);
            
            if (json.has("externalIds")) {
                JsonNode externalIds = json.get("externalIds");
                
                if (externalIds.isArray() && externalIds.size() > 0) {
                    JsonNode firstExternalId = externalIds.get(0);
                    
                    if (firstExternalId.has("value")) {
                        String externalId = firstExternalId.get("value").asText();
                        logger.info("External ID 파싱 성공: " + externalId);
                        return externalId;
                    }
                }
            }
            
            logger.warn("External ID를 찾을 수 없습니다");
            return null;

        } catch (Exception e) {
            logger.error("External ID 추출 중 오류 발생", e);
            return null;
        }
    }

    /**
     * JSON 응답에서 첫 번째 organization의 department 값 추출
     */
    private String extractDepartment(String responseBody) {
        try {
            logger.info("Department 추출 시도 중...");
            
            ObjectMapper mapper = new ObjectMapper();
            JsonNode json = mapper.readTree(responseBody);
            
            if (json.has("organizations")) {
                JsonNode organizations = json.get("organizations");
                
                if (organizations.isArray() && organizations.size() > 0) {
                    JsonNode firstOrg = organizations.get(0);
                    
                    if (firstOrg.has("department")) {
                        String department = firstOrg.get("department").asText();
                        logger.info("Department 파싱 성공: " + department);
                        return department;
                    }
                }
            }
            
            logger.warn("Department를 찾을 수 없습니다");
            return null;

        } catch (Exception e) {
            logger.error("Department 추출 중 오류 발생", e);
            return null;
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin 이벤트는 무시
    }

    @Override
    public void close() {
        System.out.println("POC: MinimalEventListener closed");
    }
}