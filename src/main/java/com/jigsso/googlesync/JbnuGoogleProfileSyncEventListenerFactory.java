package com.jigsso.googlesync;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.jboss.logging.Logger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

/**
 * 전북대학교 구글 프로필 동기화 이벤트 리스너 팩토리
 */
public class JbnuGoogleProfileSyncEventListenerFactory implements EventListenerProviderFactory {

    private static final Logger logger = Logger.getLogger(JbnuGoogleProfileSyncEventListenerFactory.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String PROVIDER_ID = "jbnu-google-profile-sync";
    
    // 수강 정보 캐시 (학번 → 수강과목 리스트)
    private static volatile Map<String, List<String>> COURSE_MAPPING_CACHE = null;
    private static final Object CACHE_LOCK = new Object();
    
    private String classmapFilePath;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new JbnuGoogleProfileSyncEventListener(session, classmapFilePath);
    }

    @Override
    public void init(Config.Scope config) {
        // KC_SPI_EVENT_LISTENER_JBNU_GOOGLE_PROFILE_SYNC_CLASSMAP_FILE_PATH 읽기
        classmapFilePath = config.get("classmap-file-path", "/opt/keycloak/data/classmap.json");
        
        logger.info("전북대 구글 프로필 동기화 이벤트 리스너 팩토리가 초기화되었습니다");
        logger.info("수업 매핑 파일 경로 설정: " + classmapFilePath);
        
        // 파일 존재 여부 및 읽기 권한 검증
        validateClassmapFile();
    }
    
    private void validateClassmapFile() {
        if (classmapFilePath == null || classmapFilePath.trim().isEmpty()) {
            logger.warn("수업 매핑 파일 경로가 설정되지 않았습니다");
            return;
        }
        
        File classmapFile = new File(classmapFilePath);
        if (!classmapFile.exists()) {
            logger.warn("수업 매핑 파일이 존재하지 않습니다: " + classmapFilePath);
        } else if (!classmapFile.canRead()) {
            logger.warn("수업 매핑 파일 읽기 권한이 없습니다: " + classmapFilePath);
        } else {
            logger.info("수업 매핑 파일 검증 완료: " + classmapFilePath);
        }
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
    
    /**
     * 학번으로 수강 과목 조회 (캐시 사용)
     */
    public static List<String> getCoursesByStudentId(String studentId, String classmapFilePath) {
        if (studentId == null || studentId.trim().isEmpty()) {
            return null;
        }
        
        // Lazy loading: 캐시가 없으면 초기화
        if (COURSE_MAPPING_CACHE == null) {
            synchronized (CACHE_LOCK) {
                if (COURSE_MAPPING_CACHE == null) {
                    COURSE_MAPPING_CACHE = loadCourseMapping(classmapFilePath);
                }
            }
        }
        
        return COURSE_MAPPING_CACHE.get(studentId);
    }
    
    /**
     * JSON 파일에서 수강 정보를 읽어서 캐시로 로드
     */
    private static Map<String, List<String>> loadCourseMapping(String classmapFilePath) {
        long startTime = System.currentTimeMillis();
        Map<String, List<String>> courseMapping = new HashMap<>();
        
        if (classmapFilePath == null || classmapFilePath.trim().isEmpty()) {
            logger.warn("수업 매핑 파일 경로가 설정되지 않음 - 빈 캐시로 초기화");
            return courseMapping;
        }
        
        try {
            File classmapFile = new File(classmapFilePath);
            if (!classmapFile.exists()) {
                logger.warn("수업 매핑 파일이 존재하지 않음: " + classmapFilePath + " - 빈 캐시로 초기화");
                return courseMapping;
            }
            
            logger.info("수업 매핑 파일 캐시 로딩 시작: " + classmapFilePath);
            
            // JSON 파일 파싱
            JsonNode rootNode = OBJECT_MAPPER.readTree(classmapFile);
            
            // 각 학번별로 수강 과목 추출
            rootNode.fieldNames().forEachRemaining(studentId -> {
                JsonNode coursesNode = rootNode.get(studentId);
                
                if (coursesNode != null && coursesNode.isArray()) {
                    List<String> courses = new ArrayList<>();
                    for (JsonNode courseNode : coursesNode) {
                        String course = courseNode.asText();
                        if (course != null && !course.trim().isEmpty()) {
                            courses.add(course.trim());
                        }
                    }
                    
                    if (!courses.isEmpty()) {
                        // 불변 리스트로 저장하여 메모리 최적화
                        courseMapping.put(studentId, Collections.unmodifiableList(courses));
                    }
                }
            });
            
            long loadTime = System.currentTimeMillis() - startTime;
            logger.info("수업 매핑 캐시 로딩 완료 - 학생 수: " + courseMapping.size() + 
                       ", 소요시간: " + loadTime + "ms");
            
        } catch (IOException e) {
            logger.error("수업 매핑 파일 읽기 중 오류 발생: " + classmapFilePath + " - 빈 캐시로 초기화", e);
        } catch (Exception e) {
            logger.error("수업 매핑 캐시 로딩 중 예상치 못한 오류 발생 - 빈 캐시로 초기화", e);
        }
        
        return courseMapping;
    }
}