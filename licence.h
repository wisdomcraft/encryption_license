#ifndef _LICENCE_H_
#define _LICENCE_H_
#include <iostream>
#include "tool.h"
#include "sha1.h"
#include "des3.h"

using namespace std;


class CWLicence
{
private:
    int     m_len_factor;
    void    gen_hash_str( const string & sin, string & sout );              //生成sha1, 40位长度, 小写字母, 取前32位长度
    bool    gen_trans_key( const string & sfactor, string & strans );       //生成密钥key
    bool    get_local_feature( string & sft_plain, string & sfactor );      //生成本地特征, 围绕着硬盘UUID与主机的hostid
    bool    _get_local1( string & sout );                                   //获取本地硬盘UUID等唯一ID的sha1, 取前32位长度
    bool    _get_local2( string & sout );                                   //获取本机的hostid, sha1并取前32位长度
    bool    feature_code_encrypt( const string & sfactor, const string & sft_plain, string & sout );    //本地特征码的加密
    bool    feature_code_decrypt( const string & sfactor, const string & sft_cipher, string & sout );   //本地特征码的解密
public:
    CWLicence();    //构造函数
    ~CWLicence();   //析构函数
    //生成本地码
    bool    GetLocalCode( string & localcode, string & localID );
    //生成序列号
    bool    SetAuthData( const string & localID, const string & sft_cipher, const string & sday, const string & spoint, const string & stype, string & sout );
    //根据序列号获取本机认证信息
    bool    GetAuthData( const string & sin, string & sout );
    //根据序列号获取指定主机的认证信息
    bool    GetAuthData( const string & sin, const string & local_id, const string & local_code, string & sout );
};


#endif