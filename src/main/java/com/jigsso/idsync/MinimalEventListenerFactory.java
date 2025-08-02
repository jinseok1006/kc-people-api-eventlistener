package com.jigsso.idsync;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * 최소한의 Event Listener Factory (등록 확인용 POC)
 */
public class MinimalEventListenerFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "minimal-event-listener";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        System.out.println("POC: Creating MinimalEventListener instance");
        return new MinimalEventListener(session);
    }

    @Override
    public void init(Config.Scope config) {
        System.out.println("POC: MinimalEventListenerFactory initialized - Registration successful!");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        System.out.println("POC: MinimalEventListenerFactory post-initialized");
    }

    @Override
    public void close() {
        System.out.println("POC: MinimalEventListenerFactory closed");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}