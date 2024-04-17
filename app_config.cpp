#include <iostream>
#include "app_config.h"
#include "licence.h"
#include "tool.h"

using namespace std;


//构造函数
CAppConfig::CAppConfig()
{
    getCfgFromEnv( m_cfgPath, ENV_CFG_PATH );
    if ( m_cfgPath.end()[ 0 ] != '/' ) m_cfgPath += '/';
}


//析造函数
CAppConfig::~CAppConfig()
{
}


//从CentOS系统变量中获取设置
int CAppConfig::getCfgFromEnv( string & dst, const char * envName )
{
    char * p = getenv( envName );
    if ( NULL == p )
    {
        cout << "Environment variables are not configured![" << envName << "]" << endl;
        return -1;
    }
    
    dst = p;
    return 0;
}


//读取文件并检查授权码
bool CAppConfig::ReadLicenceFile( long & lday, long & lpoint, long & ltype )
{
    CWLicence wLicence;
    string slic;
    string slicfile;
    slicfile = m_cfgPath;
    slicfile += "lic.hy";
    
    if ( file_block_read( slicfile.c_str(), slic ) <= 0 )
    {
        cout << "read licence file error : " << slicfile;
        return false;
    }
    
    str_clear_all( slic, "\r\n " );
    cout << "|" << slic << "|" << endl;
    if ( slic.length() != 32 )
    {
        cout << "read licence file length error : " << slicfile;
        return false;
    }
    
    string sauth;
    if ( ! wLicence.GetAuthData( slic, sauth ) )
    {
        cout << "read licence get auth error : " << slic;
        return false;
    }
    
    string spart1 = sauth.substr( 0, 16 );
    string spart2 = sauth.substr( 16, 16 );
    
    cout << "spart1: " << spart1 << endl;
    cout << "spart2: " << spart2 << endl;
    if ( spart1[ 0 ] != 'f' || spart1[ 1 ] != 'f' || spart1[ 10 ] != 'f' || spart1[ 11 ] != 'f' )
    {
        cout << "read licence auth str error : " << sauth;
        return false;
    }
    if ( spart2[ 0 ] != 'f' || spart2[ 1 ] != 'f' || spart2[ 7 ] != 'f' || spart2[ 8 ] != 'f' )
    {
        cout << "read licence auth str error : " << sauth;
        return false;
    }
    
    return true;
}

