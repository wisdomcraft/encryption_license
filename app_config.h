#ifndef _APP_CONFIG_H_
#define _APP_CONFIG_H_
#include <iostream>
using namespace std;

#define ENV_CFG_PATH "CFGPATH"

class CAppConfig
{
private:
    int getCfgFromEnv( string & dst, const char * envName );            //从CentOS系统变量中获取设置
public:
    string m_cfgPath;   //配置文件目录路径
    CAppConfig();       //构造函数
    ~CAppConfig();      //析构函数
    bool ReadLicenceFile( long & lday, long & lpoint, long & ltype );   //读取文件并检查授权码
};

#endif

