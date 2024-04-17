#include <iostream>
#include <string.h>     //strcmp()
#include "licence.h"
#include "app_config.h"
#include "tool.h"
#include "sha1.h"
#include "des3.h"

using namespace std;

/*
*********************结构体*********************
*/


struct{
    string action;
    string day;
    string point;
    string type;
    string local_id;
    string local_code;
    string license;
} config;


/*
*********************自定义函数*********************
*/

//帮助函数
void help();

//初始化
void init(int argc, char *argv[]);

//参数检查
bool argumentCheck();

//判断一个字符串是否为整形
int isNumeric(string str);

/*
*********************入口函数*********************
*/
int main( int argc,char *argv[] )
{
    if( argc < 2)
    {
        cout << "error, argc too less" << endl;
        help();
        return 0;
    }
    
    //初始化
    init(argc, argv);
    
    //参数检查
    if( !argumentCheck() )
    {
        help();
        return 0;
    }
    
    //获取本地特征码
    if( config.action == "get_local_feature" )
    {
        CWLicence wLicence;
        string stringCode, stringID;
        if( !wLicence.GetLocalCode( stringCode, stringID ) )
        {
            cout << "error, get local feature failed" << endl;;
            return 0;
        }
        cout << "success" << endl;
        cout << "local_id:  \t" << stringID << endl;
        cout << "local_code:\t" << stringCode << endl;
        return 0;
    }
    
    //生成序列号
    if( config.action == "generate_license" )
    {
        CWLicence wLicence;
        if( config.local_id == "" || config.local_code == "" )
        {
            string stringCode, stringID;
            if( !wLicence.GetLocalCode( stringCode, stringID ) )
            {
                cout << "error, get local feature failed" << endl;;
                return 0;
            }
            config.local_id     = stringID;
            config.local_code   = stringCode;
        }
        
        string local_id     = config.local_id;   //这个要32位长度  本地码中的id
        string local_code   = config.local_code;   //本地码中的code
        string stringDay    = config.day;
        string stringPoint  = config.point;
        string stringType   = config.type;
        string stringOut;
        if(!wLicence.SetAuthData(local_id, local_code, stringDay, stringPoint, stringType, stringOut))
        {
            cout << "error, generate license number failed in set_auth_data" << endl;
        }
        
        cout << "success, generate license number: " << stringOut << endl;
        return 0;
    }
    
    //验证序列号
    if( config.action == "check_license" )
    {
        CWLicence wLicence;
        string stringAuth;
        string license      = config.license;
        string local_id     = config.local_id;
        string local_code   = config.local_code;
        bool result         = false;
        if( config.local_id == "" || config.local_code == "" )
        {
            //本地主机
            result = wLicence.GetAuthData( license, stringAuth );
        }else
        {
            //指定主机
            result = wLicence.GetAuthData( license, local_id, local_code, stringAuth );
        }
        if( !result )
        {
            cout << "error, check license failed, license: " << license << endl;
            return 0;
        }
        
        string stringPart1 = stringAuth.substr( 0, 16 );
        string stringPart2 = stringAuth.substr( 16, 16 );
        
        if( stringPart1[0] != 'f' || stringPart1[1] != 'f' || stringPart1[10] != 'f' || stringPart1[11] != 'f' )
        {
            cout << "failed, licence number is incorrect after decrypt by check" << endl;
            return 0;
        }
        
        if( stringPart2[0] != 'f' || stringPart2[1] != 'f' || stringPart2[7] != 'f' || stringPart2[8] != 'f' )
        {
            cout << "failed, licence number is incorrect after decrypt by check" << endl;
            return 0;
        }
        
        long longDay= 0, longPoint = 0, longType = 0;
        longDay     = atol( stringPart1.substr( 2, 8 ).c_str() );
        longPoint   = atol( stringPart2.substr( 2, 5 ).c_str() );
        longType    = atol( stringPart2.substr( 9, 1 ).c_str() );
        cout << "success, check licence information, day: " << longDay << ", point: " << longPoint << ", type: " << longType << endl;
        
        return 0;
    }
    
    return 0;
}


//帮助函数的实现
void help()
{
    cout << endl;
    cout << "get_local_feature \t"  << "action, get location feature local_id and local_code" << endl;
    cout << "generate_license\t"    << "action, generate license number" << endl;
    cout << "\t day         \t"     << "day, for example, 20230210" << endl;
    cout << "\t point       \t"     << "point, for example, 300" << endl;
    cout << "\t type        \t"     << "type, for example, 1" << endl;
    cout << "\t local_id    \t"     << "local id, default this server if not exist, 32 length string" << endl;
    cout << "\t local_code  \t"     << "local code, default this server if not exist, 32 length string" << endl;
    cout << "check_license\t\t"     << "action, verify license number" << endl;
    cout << "\t license      \t"    << "license number, 32 length string" << endl;
    cout << "\t local_id    \t"     << "local id, default this server if not exist, 32 length string" << endl;
    cout << "\t local_code  \t"     << "local code, default this server if not exist, 32 length string" << endl;
}


//初始化
void init(int argc, char *argv[])
{
    for(int i=1;i<argc;i++)
    {
        int intLength = strlen(argv[i]);
        if(intLength < 3)
        {
            continue;
        }
        
        //如果参数中没有等号, 则进入下一循环
        int intPosition = -1;
        for(int j=0;j<strlen(argv[i]);j++)
        {
            if(argv[i][j] == '=')
            {
                intPosition = j;
                break;
            }
        }
        if(intPosition==-1 || intPosition==0 || intPosition==intLength-1) continue;
        
        //获取key与value
        char key[intPosition+1];
        char value[intLength-intPosition];
        int intStep = 0;
        for(int j=0;j<intPosition;j++)
        {
            key[intStep] = argv[i][j];
            intStep++;
        }
        key[intStep] = '\0';
        intStep = 0;
        for(int j=intPosition+1;j<intLength;j++)
        {
            value[intStep] = argv[i][j];
            intStep++;
        }
        value[intStep] = '\0';
        
        //获取并赋值具体的参数
        if(strcmp(key, "action") == 0)
        {
            config.action   = value;
        }
        else if(strcmp(key, "day") == 0)
        {
            config.day      = value;
        }
        else if(strcmp(key, "point") == 0)
        {
            config.point    = value;
        }
        else if(strcmp(key, "type") == 0)
        {
            config.type     = value;
        }
        else if(strcmp(key, "local_id") == 0)
        {
            config.local_id = value;
        }
        else if(strcmp(key, "local_code") == 0)
        {
            config.local_code = value;
        }
        else if(strcmp(key, "license") == 0)
        {
            config.license  = value;
        }
    }
}


//参数检查
bool argumentCheck()
{
    if( config.action == "" )
    {
        cout << "error, action empty in command line" << endl;
        return false;
    }
    else if( config.action != "get_local_feature" && config.action != "generate_license" && config.action != "check_license" )
    {
        cout << "error, action is incorrect in command line" << endl;
        return false;
    }
    
    if( config.action == "generate_license" )
    {
        if( config.day == "" )
        {
            cout << "error, day empty in command line when action=generate_license" << endl;
            return false;
        }
        else if( config.day.length() != 8 )
        {
            cout << "error, day length is not 8 in command line when action=generate_license" << endl;
            return false;
        }
        else if( isNumeric(config.day) != 1 )
        {
            cout << "error, day is not intger in command line when action=generate_license" << endl;
            return false;
        }
        if( config.point == "" )
        {
            cout << "error, point empty in command line when action=generate_license" << endl;
            return false;
        }
        else if( config.point.length() != 3 )
        {
            cout << "error, point length is not 3 in command line when action=generate_license" << endl;
            return false;
        }
        else if( isNumeric(config.point) != 1 )
        {
            cout << "error, point is not intger in command line when action=generate_license" << endl;
            return false;
        }
        if( config.type == "" )
        {
            cout << "error, type empty in command line when action=generate_license" << endl;
            return false;
        }
        else if( config.type.length() != 1 )
        {
            cout << "error, type length is not 1 in command line when action=generate_license" << endl;
            return false;
        }
        else if( isNumeric(config.type) != 1 )
        {
            cout << "error, type is not intger in command line when action=generate_license" << endl;
            return false;
        }
        if( (config.local_id == "" && config.local_code != "") || (config.local_id != "" && config.local_code == "") )
        {
            cout << "error, local_id and local_code should both empty or exist" << endl;
            return false;
        }
        else if( config.local_id != "")
        {
            if( config.local_id.length() != 32 )
            {
                cout << "error, local_id exist but its length is not 32 in command line when action=generate_license" << endl;
                return false;
            }
        }
        else if( config.local_code != "")
        {
            if( config.local_code.length() != 32 )
            {
                cout << "error, local_code exist but its length is not 32 in command line when action=generate_license" << endl;
                return false;
            }
        }
    }
    else if( config.action == "check_license" )
    {
        if( config.license == "" )
        {
            cout << "error, license empty in command line" << endl;
            return false;
        }
        if( (config.local_id == "" && config.local_code != "") || (config.local_id != "" && config.local_code == "") )
        {
            cout << "error, local_id and local_code should both empty or exist" << endl;
            return false;
        }
        else if( config.local_id != "")
        {
            if( config.local_id.length() != 32 )
            {
                cout << "error, local_id exist but its length is not 32 in command line when action=generate_license" << endl;
                return false;
            }
        }
        else if( config.local_code != "")
        {
            if( config.local_code.length() != 32 )
            {
                cout << "error, local_code exist but its length is not 32 in command line when action=generate_license" << endl;
                return false;
            }
        }
    }
    
    return true;
}


//判断一个字符串是否为整形
//int isNumeric(char *str)
int isNumeric(string str)
{
    char *p = const_cast<char *>(str.c_str());
    if(*p == '\0')
    {
        return -1;
    }
    while(*p != '\0')
    {
        if(*p >= 48 && *p<=57)
        {
            p++;
        }else{
            return 0;
        }
    }
    return 1;
}

