package com.jigsso.googlesync;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;

import java.util.Map;
import org.jboss.logging.Logger;

/**
 * 전북대학교 구글 프로필 동기화 이벤트 리스너
 * 
 * JBNU 사용자가 구글 계정으로 로그인할 때 Google People API를 통해
 * 사용자의 조직 정보(외부 ID, 부서)를 자동으로 Keycloak 프로필에 동기화하고,
 * 모든 로그인에서 수강 정보를 동기화합니다.
 */
public class JbnuGoogleProfileSyncEventListener implements EventListenerProvider {

    private static final Logger logger = Logger.getLogger(JbnuGoogleProfileSyncEventListener.class);
    private static final String GOOGLE_PROVIDER_ID = "google";

    private final KeycloakSession session;
    private final GoogleProfileSyncService googleProfileSyncService;
    private final CourseInformationSyncService courseInformationSyncService;

    public JbnuGoogleProfileSyncEventListener(KeycloakSession session, String classmapFilePath) {
        this.session = session;
        this.googleProfileSyncService = new GoogleProfileSyncService(session);
        this.courseInformationSyncService = new CourseInformationSyncService(classmapFilePath, session);
        logger.trace("전북대 구글 프로필 동기화 이벤트 리스너가 생성되었습니다");
    }

    @Override
    public void onEvent(Event event) {
        // 모든 이벤트에 대해 간단한 로그만 출력
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

        // 현재 로그인 세션의 identity provider 확인
        Map<String, String> eventDetails = event.getDetails();
        String currentIdentityProvider = null;
        if (eventDetails != null) {
            currentIdentityProvider = eventDetails.get("identity_provider");
        }

        logger.info("로그인 이벤트 감지됨");
        logger.info("사용자ID: " + userId);
        logger.info("영역ID: " + realmId);
        logger.info("현재 로그인 방식: " + (currentIdentityProvider != null ? currentIdentityProvider : "로컬 로그인"));

        // 로컬 로그인인 경우 구글 프로필 동기화는 생략하지만 수강 정보는 처리
        if (currentIdentityProvider == null) {
            logger.info("로컬 로그인 감지 - 구글 프로필 동기화를 생략하고 수강 정보만 동기화합니다");
        } else if (!GOOGLE_PROVIDER_ID.equals(currentIdentityProvider)) {
            logger.info("구글이 아닌 IdP 로그인 감지 (" + currentIdentityProvider + ") - 구글 프로필 동기화를 생략하고 수강 정보만 동기화합니다");
        }

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

        // 1. 구글 프로필 동기화 (구글 로그인 시에만 실행)
        if (GOOGLE_PROVIDER_ID.equals(currentIdentityProvider)) {
            logger.debug("구글 로그인 감지 - 구글 프로필 동기화 실행");
            // Google Identity 처리 - Stream을 직접 사용하여 성능 최적화
            session.users().getFederatedIdentitiesStream(realm, user)
                .filter(identity -> GOOGLE_PROVIDER_ID.equals(identity.getIdentityProvider()))
                .findFirst()
                .ifPresent(identity -> googleProfileSyncService.processGoogleIdentity(identity, user, realm));
        }

        // 2. 수강 정보 동기화 (모든 로그인에서 실행)
        logger.debug("수강 정보 동기화 실행 - 로그인 방식: " + (currentIdentityProvider != null ? currentIdentityProvider : "로컬"));
        courseInformationSyncService.syncCourseInformation(user, realm);
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin 이벤트는 무시
    }

    @Override
    public void close() {
        logger.trace("전북대 구글 프로필 동기화 이벤트 리스너가 종료되었습니다");
    }
}