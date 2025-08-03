package com.jigsso.googlesync;

import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.ModelToRepresentation;
import org.jboss.logging.Logger;

import java.util.List;

/**
 * 수강 정보 동기화 서비스
 * 
 * 로컬 JSON 파일에서 학번을 통해 수강 과목 정보를 조회하고
 * 사용자 프로필에 동기화하는 기능을 담당합니다.
 */
public class CourseInformationSyncService {

    private static final Logger logger = Logger.getLogger(CourseInformationSyncService.class);

    private final String classmapFilePath;
    private final KeycloakSession session;

    public CourseInformationSyncService(String classmapFilePath, KeycloakSession session) {
        this.classmapFilePath = classmapFilePath;
        this.session = session;
    }

    /**
     * 사용자의 수강 정보를 동기화 (모든 로그인에서 실행)
     */
    public void syncCourseInformation(UserModel user, RealmModel realm) {
        if (user == null) {
            logger.warn("사용자가 null이어서 수강 정보 동기화 불가");
            return;
        }
        
        if (realm == null) {
            logger.warn("영역이 null이어서 수강 정보 동기화 불가");
            return;
        }
        
        logger.debug("수강 정보 동기화 시작: " + user.getUsername());
        
        // 사용자에서 학번 추출
        String studentId = extractStudentId(user);
        if (studentId == null) {
            logger.debug("학번을 추출할 수 없어 수강 정보 동기화 생략: " + user.getUsername());
            return;
        }
        
        // JSON 파일에서 수강 과목 조회
        List<String> courses = loadCoursesFromMapping(studentId);
        if (courses != null && !courses.isEmpty()) {
            // 1. 사용자 속성에 수강 과목 저장
            user.setAttribute("courses", courses);
            
            // 2. 수업별 그룹 및 역할 생성하고 사용자 추가
            createGroupsRolesAndAddUser(courses, user, realm);
            
            logger.info("사용자 " + user.getUsername() + "의 수강 정보 동기화 완료 - 과목 수: " + courses.size());
        } else {
            logger.debug("사용자 " + user.getUsername() + " (학번: " + studentId + ")의 수강 정보가 없음");
        }
    }

    /**
     * 수업별 그룹 및 역할을 생성하고 사용자를 그룹에 추가
     */
    private void createGroupsRolesAndAddUser(List<String> courses, UserModel user, RealmModel realm) {
        for (String course : courses) {
            try {
                // 1. 그룹 생성 또는 조회 (/course/과목명)
                GroupModel courseGroup = createOrGetCourseGroup(course, realm);
                
                // 2. Realm Role 생성 또는 조회 (course:과목명)
                RoleModel courseRole = createOrGetCourseRole(course, realm);
                
                // 3. 그룹에 역할 부여
                courseGroup.grantRole(courseRole);
                
                // 4. 사용자를 그룹에 추가
                if (!user.isMemberOf(courseGroup)) {
                    user.joinGroup(courseGroup);
                    logger.info("사용자 " + user.getUsername() + "를 그룹 " + courseGroup.getName() + "에 추가");
                } else {
                    logger.debug("사용자 " + user.getUsername() + "는 이미 그룹 " + courseGroup.getName() + "의 멤버");
                }
                
            } catch (Exception e) {
                logger.error("수업 " + course + "에 대한 그룹/역할 처리 중 오류 발생", e);
            }
        }
    }
    
    /**
     * 수업 그룹 생성 또는 조회 (/course/과목명)
     */
    private GroupModel createOrGetCourseGroup(String course, RealmModel realm) {
        String groupName = course; // 그룹명: 과목명 그대로
        String groupPath = "/course/" + course; // 그룹 경로: /course/과목명
        
        // 기존 그룹 검색 (경로로 검색)
        GroupModel existingGroup = findGroupByPath(groupPath, realm);
        if (existingGroup != null) {
            logger.debug("기존 그룹 발견: " + groupPath);
            return existingGroup;
        }
        
        // course 상위 그룹 생성 또는 조회
        GroupModel courseParentGroup = findGroupByPath("/course", realm);
        if (courseParentGroup == null) {
            courseParentGroup = realm.createGroup("course");
            logger.info("상위 그룹 생성: /course");
        }
        
        // 하위 그룹 생성
        GroupModel newGroup = realm.createGroup(groupName, courseParentGroup);
        logger.info("새 수업 그룹 생성: " + groupPath);
        
        return newGroup;
    }
    
    /**
     * 수업 Realm Role 생성 또는 조회 (course:과목명)
     */
    private RoleModel createOrGetCourseRole(String course, RealmModel realm) {
        String roleName = "course:" + course; // 역할명: course:과목명
        
        // 기존 역할 검색
        RoleModel existingRole = realm.getRole(roleName);
        if (existingRole != null) {
            logger.debug("기존 역할 발견: " + roleName);
            return existingRole;
        }
        
        // 새 역할 생성
        RoleModel newRole = realm.addRole(roleName);
        newRole.setDescription("수업 " + course + "에 대한 역할");
        logger.info("새 수업 역할 생성: " + roleName);
        
        return newRole;
    }
    
    /**
     * 그룹 경로로 그룹 검색
     */
    private GroupModel findGroupByPath(String path, RealmModel realm) {
        return realm.getGroupsStream()
            .filter(group -> path.equals(ModelToRepresentation.buildGroupPath(group)))
            .findFirst()
            .orElse(null);
    }

    /**
     * 캐시에서 학번에 해당하는 수강 과목 목록을 조회
     */
    private List<String> loadCoursesFromMapping(String studentId) {
        if (studentId == null || studentId.trim().isEmpty()) {
            logger.debug("학번이 null이거나 비어있어 수강 정보 조회 불가");
            return null;
        }
        
        try {
            logger.debug("캐시에서 학번 조회 시작: " + studentId);
            
            // Factory의 캐시에서 조회 (디스크 I/O 없음)
            List<String> courses = JbnuGoogleProfileSyncEventListenerFactory.getCoursesByStudentId(studentId, classmapFilePath);
            
            if (courses != null && !courses.isEmpty()) {
                logger.info("학번 " + studentId + "의 수강 과목 " + courses.size() + "개 캐시 조회 완료: " + courses);
                return courses;
            } else {
                logger.debug("학번 " + studentId + "에 대한 수강 정보를 캐시에서 찾을 수 없음");
            }
            
        } catch (Exception e) {
            logger.error("수강 정보 캐시 조회 중 예상치 못한 오류 발생", e);
        }
        
        return null;
    }

    /**
     * 사용자에서 학번을 추출 (externalId 속성에서만 추출)
     */
    private String extractStudentId(UserModel user) {
        if (user == null) {
            logger.warn("사용자가 null이어서 학번 추출 불가");
            return null;
        }
        
        // externalId 속성에서만 추출 (구글에서 동기화된 학번)
        String externalId = user.getFirstAttribute("externalId");
        if (externalId != null && !externalId.trim().isEmpty()) {
            logger.debug("externalId에서 학번 추출: " + externalId);
            return externalId.trim();
        }
        
        logger.debug("사용자 " + user.getUsername() + "에 externalId가 없어 수강 정보 동기화 생략");
        return null;
    }
}