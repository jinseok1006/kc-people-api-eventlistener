package com.jigsso.googlesync;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * 전북대 구글 프로필 동기화 테스트
 */
public class JbnuGoogleProfileSyncTest 
    extends TestCase
{
    /**
     * 테스트 케이스 생성
     *
     * @param testName 테스트 케이스명
     */
    public JbnuGoogleProfileSyncTest( String testName )
    {
        super( testName );
    }

    /**
     * @return 테스트 스위트
     */
    public static Test suite()
    {
        return new TestSuite( JbnuGoogleProfileSyncTest.class );
    }

    /**
     * 기본 테스트
     */
    public void testBasic()
    {
        assertTrue( true );
    }
}
