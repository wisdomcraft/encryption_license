#include <vector>       //vector
#include <map>          //map
#include <unistd.h>     //gethostid()
#include "licence.h"
#include "tool.h"
#include "sha1.h"
#include "des3.h"

using namespace std;


//构造函数
CWLicence::CWLicence()
{
    m_len_factor = 16;
}


//析构函数
CWLicence::~CWLicence()
{}


//生成sha1, 40位长度, 小写字母, 取前32位长度
void CWLicence::gen_hash_str( const string & sin, string & sout )
{
    char sbuf[ 16 ];
    unsigned int hash_ret[ 5 ] = { 0 };
    SHA1 sha1;
    sha1.Reset();
    sha1 << sin.c_str();
    sha1.Result( hash_ret );

    string strt;
    for ( int i = 0; i < 5; i ++ )
    {
        snprintf( sbuf, sizeof( sbuf ), "%08x", hash_ret[ i ] );
        strt += sbuf;
    }
    if ( strt.length() > 32 )
        sout = strt.substr( 0, 32 );
    else
        sout = strt;
}


//生成密钥key
bool CWLicence::gen_trans_key( const string & sfactor, string & strans )
{
    if ( sfactor.length() != m_len_factor )
    {
        printerr( "factor code input err!\n" );
        return false;
    }
    
    string sctx;
    sctx += 0x71;
    sctx += 0x71;
    sctx += 0x3d;
    sctx += 0x31;
    sctx += 0x39;
    sctx += 0x30;
    sctx += 0x39;
    sctx += 0x38;
    sctx += 0x37;
    sctx += 0x35;
    sctx += 0x35;
    sctx += 0x2c;
    sctx += 0x65;
    sctx += 0x7a;
    sctx += 0x68;
    sctx += 0x69;
    sctx += 0x6c;
    sctx += 0x6f;
    sctx += 0x6e;
    sctx += 0x67;
    sctx += 0x40;
    sctx += 0x68;
    sctx += 0x6f;
    sctx += 0x74;
    sctx += 0x6d;
    sctx += 0x61;
    sctx += 0x69;
    sctx += 0x6c;
    sctx += 0x2e;
    sctx += 0x63;
    sctx += 0x6f;
    sctx += 0x6d;
    sctx += sfactor;
    
    gen_hash_str( sctx, strans );
    return true;
}


//生成本地特征, 围绕着硬盘UUID与主机的hostid
bool CWLicence::get_local_feature( string & sft_plain, string & sfactor )
{
    string sfactor1, sfactor2;
    int lenfactorsub;
    string sl1, sl2, sctx;
    
    lenfactorsub = m_len_factor / 2;
    
    for ( int i = 0; i < lenfactorsub; i ++ )
    {
        sfactor1.append( "0" );
        sfactor2.append( "0" );
    }
    
    if ( _get_local1( sl1 ) )
        sfactor1 = sl1.substr( 3, lenfactorsub );
    
    if ( _get_local2( sl2 ) )
        sfactor2 = sl2.substr( 3, lenfactorsub );
    
    sfactor = sfactor1;
    sfactor += sfactor2;
    
    if ( sl1.empty() && sl2.empty() )
        return false;
    
    sctx = sl1;
    sctx += 123;
    sctx += 87;
    sctx += 76;
    sctx += 56;
    sctx += 56;
    sctx += 56;
    sctx += 125;
    sctx += sl2;
    
    gen_hash_str( sctx, sft_plain );
    return true;
}


//获取本地硬盘UUID等唯一ID的sha1, 取前32位长度
bool CWLicence::_get_local1( string & sout )
{
    vector<string>      vec_line;
    map<string, string> map_uuid;
    map<string, string> map_ptuuid;
    
    string sctx;
    string scmd;
    scmd = "/usr/sbin/blkid";
    
    //执行cmd命令, 获取输出的结果
    app_call_popen( scmd.c_str(), sctx );
    
    //将cmd的执行结果字符串, 转换为向量
    str_split_delimeter( sctx, ' ', vec_line );
    
    if ( vec_line.size() == 0 )
        return false;
    
    for ( auto & x : vec_line )
    {
        vector<string> vec_kv;
        if ( x.find( "UUID" ) == 0 )
        {
            str_split_delimeter( x, '=', vec_kv );
            if ( vec_kv.size() == 2 )
            {
                str_clear_all( vec_kv[ 1 ], "\"" );
                map_uuid.insert( pair<string, string>( vec_kv[ 1 ], vec_kv[ 0 ] ) );
            }
        }
        else if ( ( x.find( "PARTUUID" ) == 0 ) || ( x.find( "PTUUID" ) == 0 ) )
        {
            str_split_delimeter( x, '=', vec_kv );
            if ( vec_kv.size() == 2 )
            {
                str_clear_all( vec_kv[ 1 ], "\"" );
                map_ptuuid.insert( pair<string, string>( vec_kv[ 1 ], vec_kv[ 0 ] ) );
            }
        }
    }
    
    map<string, string> * pmap = nullptr;
    if ( map_uuid.size() > 0 )
        pmap = & map_uuid;
    else if ( map_ptuuid.size() > 0 )
        pmap = & map_ptuuid;
    
    if ( nullptr == pmap )
        return false;
    
    string::size_type i = 0;
    sctx.clear();
    for ( auto & x : * pmap )
    {
        const string & skey = x.first;
        if ( skey.length() > 2 )
        {
            i ++;
            sctx += skey.substr( i, skey.length() - i );
            sctx += "|";

            if ( i > 10 )
            {
                break;
            }
        }
        else
            sctx += ( char ) ( i + 48 );
    }
    
    gen_hash_str( sctx, sout );
    return true;
}


//获取本机的hostid, sha1并取前32位长度
bool CWLicence::_get_local2( string & sout )
{
    long result;
    if ( -1 == ( result = gethostid() ) )
    {
        return false;
    }
    
    string sctx;
    str_from_ulong( ( unsigned long ) result, sctx );
    gen_hash_str( sctx, sout );
    
    return true;
}


//本地特征码的加密
bool CWLicence::feature_code_encrypt( const string & sfactor, const string & sft_plain, string & sout )
{
    string stranskey;
    if ( ! gen_trans_key( sfactor, stranskey ) )
        return false;
    
    string strt;
    string sbyte;
    hex_to_str( sft_plain, sbyte );
    
    if ( ! DES3_Encrypt( stranskey, sbyte, strt ) )
        return false;
    
    str_to_hex( strt, sout, 0 );
    return true;
}


//本地特征码的解密
bool CWLicence::feature_code_decrypt( const string & sfactor, const string & sft_cipher, string & sout )
{
    string stranskey;
    if ( ! gen_trans_key( sfactor, stranskey ) )
        return false;
    
    string strt;
    string sbyte;
    hex_to_str( sft_cipher, sbyte );
    //buffer_hex_print( sbyte.c_str(), sbyte.length(), cout, "sbyte" );
    
    if ( ! DES3_Decrypt( stranskey, sbyte, strt ) )
        return false;
    
    str_to_hex( strt, sout, 0 );
    return true;
}


//生成本地码
bool CWLicence::GetLocalCode( string & localcode, string & localID )
{
    string sfeature, sfactor;
    if ( ! get_local_feature( sfeature, sfactor ) )
        return false;
    
    string sft_hash;
    gen_hash_str( sfeature, sft_hash );
    
    localID = sfactor;
    localID += sft_hash.substr( 0, 32 - m_len_factor );
    
    return feature_code_encrypt( sfactor, sfeature, localcode );
}


bool CWLicence::SetAuthData( const string & localID, const string & sft_cipher, const string & sday, const string & spoint, const string & stype, string & sout )
{
    string sfeature, sfactor;
    
    if ( localID.length() != 32 )
        return false;
    
    sfactor = localID.substr( 0, m_len_factor );
    
    if ( ! feature_code_decrypt( sfactor, sft_cipher, sfeature ) )
        return false;
    
    string sft_hash;
    gen_hash_str( sfeature, sft_hash );
    
    string in_hash = localID.substr( m_len_factor );
    if ( sft_hash.find( in_hash ) != 0 )
        return false;
    
    string strrand  = get_random_str();
    string sauth_rand;
    sauth_rand      = "ff";
    sauth_rand      += sday;
    sauth_rand      += "ff";
    sauth_rand      += strrand.substr( 0, 12 - sday.length() );
    sauth_rand      += "ff";
    sauth_rand      += spoint;
    sauth_rand      += "ab";
    sauth_rand      += "ff";
    sauth_rand      += stype;
    sauth_rand      += strrand.substr( 8, 9 - spoint.length() );
    
    string strt;
    string sbyte;
    hex_to_str( sauth_rand, sbyte );

    if ( ! DES3_Encrypt( sfeature, sbyte, strt ) )
        return false;
    
    str_to_hex( strt, sout, 0 );
    return true;
}


//根据序列号获取本机认证信息
bool CWLicence::GetAuthData( const string & sin, string & sout )
{
    //本地码DES解密输入字符串 提取keys
    string sfeature, sfactor;
    get_local_feature( sfeature, sfactor );
    
    string sbyte;
    hex_to_str( sin, sbyte );
    
    string strt;
    if ( ! DES3_Decrypt( sfeature, sbyte, strt ) )
        return false;

    str_to_hex( strt, sout, 0 );
    return true;
}



bool CWLicence::GetAuthData( const string & sin, const string & local_id, const string & local_code, string & sout )
{
    if ( local_id.length() != 32 )
        return false;
    
    string sfeature, sfactor;
    sfactor = local_id.substr( 0, m_len_factor );
    
    if ( !feature_code_decrypt( sfactor, local_code, sfeature ) )
        return false;
    
    string sbyte;
    hex_to_str( sin, sbyte );
    
    string strt;
    if ( ! DES3_Decrypt( sfeature, sbyte, strt ) )
        return false;
    
    str_to_hex( strt, sout, 0 );
    
    return true;
}

