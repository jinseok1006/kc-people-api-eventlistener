package com.jigsso.googlesync;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * 전북대학교 구글 프로필 동기화 이벤트 리스너 팩토리
 */
public class JbnuGoogleProfileSyncEventListenerFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "jbnu-google-profile-sync";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new JbnuGoogleProfileSyncEventListener(session);
    }

    @Override
    public void init(Config.Scope config) {
        // 초기화 로직 (필요시 추가)
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // 후 초기화 로직 (필요시 추가)
    }

    @Override
    public void close() {
        // 종료 로직 (필요시 추가)
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}