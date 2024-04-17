#include <cstring>      //strlen()
#include <stdio.h>      //popen()
#include <vector>       //vector
#include <sstream>      //std::stringstream
#include "tool.h"


//执行cmd命令并获取输出的结果
int app_call_popen( const char * cmd, std::string & sout )
{
    FILE* fp = NULL;
    if ( ( fp = popen( cmd, "r" ) ) == NULL )
        return -1;

    char buffer[ 260 ] = { 0 };
    while ( fgets( buffer, ( sizeof( buffer ) - 4 ), fp ) != NULL )
    {
        sout += buffer;
    }

    pclose( fp );

    return 0;
}


//通过空格将字符串分隔成向量
size_t str_split_delimeter( const std::string & strsrc, const char delimeter, std::vector<std::string> & vec_str )
{
    std::string::size_type start = 0;
    std::string::size_type pos;
    while ( ( pos = strsrc.find( delimeter, start ) ) != std::string::npos )
    {
        vec_str.push_back( strsrc.substr( start, pos - start ) );
        start = pos + 1;
    }
    
    vec_str.push_back( strsrc.substr( start, strsrc.length() - start ) );
    return vec_str.size();
}


//清除字符串中指定的子字符串
void str_clear_all( std::string & strsrc, const char * dirtychar )
{
    size_t nlen = strlen( dirtychar );
    bool bfind  = false;
    std::string::iterator it;
    
    for ( it = strsrc.begin(); it != strsrc.end(); )
    {
        bfind = false;
        for ( size_t j = 0; j < nlen; j++ )
        {
            if ( *it == dirtychar[ j ] )
            {
                bfind = true;
                break;
            }
        }
        if ( bfind == true )
            it = strsrc.erase( it );
        else
            it++;
    }
}


//将长整理long转换为string字符串
void str_from_ulong( unsigned long ulvalue, std::string & sout )
{
    char sbuf[ 64 ] = { 0 };
    snprintf( sbuf, sizeof( sbuf ), "%lu", ulvalue );
    sout = sbuf;
}


//字符串与hex的相互转换, 3DES加密时使用
size_t str_to_hex( const std::string & sdata, std::string & shex, int lower_upper )
{
    std::string hex;
    if ( 0 == lower_upper )
        hex = "0123456789abcdef";
    else
        hex = "0123456789ABCDEF";
    
    std::stringstream ss;
    std::string::size_type slen = sdata.size();

    for ( std::string::size_type i = 0; i < slen; ++i )
        ss << hex[ ( unsigned char ) sdata[ i ] >> 4 ] << hex[ ( unsigned char ) sdata[ i ] & 0xf ];
    
    shex = ss.str();
    return shex.length();
}


//字符串与hex的相互转换, 3DES加密时使用
size_t hex_to_str( const std::string & shex, std::string & sdata )
{
    std::string::size_type hlen = shex.size();

    for ( size_t i = 0; i < hlen; i += 2 )
    {
        std::string byte = shex.substr( i, 2 );
        char chr = ( char ) ( int ) strtol( byte.c_str(), NULL, 16 );
        sdata.push_back( chr );
    }
    
    return sdata.size();
}


//阻塞式读取文件
int64_t file_block_read( const std::string & filename, std::string & sout )
{
    FILE * fp = fopen( filename.c_str(), "rb" );
    if ( NULL == fp )
        return -1;
    
    unsigned short len      = 0;
    unsigned short readMax  = 1024;
    char sbuf[ 1024 ];
    
    do
    {
        sout.append( sbuf, len );
        len = fread( sbuf, 1, readMax, fp );
    } while ( len > 0 );
    
    fclose( fp );
    
    return sout.length();
}


//打印输出查看
void buffer_hex_print( const void * buffer, uint nsize, std::ostream & outobj, const char * title )
{
	std::string strt = "+-----------------------------------------------------------------------------+";
	uint ntitleLen = strlen( title );
	uint nbegin = ( strt.length() - strlen( title ) ) / 2;
	strt.replace( ( nbegin > 0 ) ? nbegin : 1, ntitleLen, title );

	outobj << "\n" << strt << "\n";

	uint nline = 0;
	uint i, j = 0;
	unsigned char cstep;
	char stmp[ 20 ];
	char shex[ 58 ] = { 0 };
	char sascii[ 20 ] = { 0 };

	memset( shex, ' ', 50 );
	memset( sascii, ' ', 16 );
	
	for ( i = 0; i < nsize; i ++ )
	{
		cstep = ( ( char * ) buffer )[ i ];
		snprintf( stmp, sizeof( stmp ), "%02x ", cstep );
		int noffset = j * 3 + j / 8 + 1;
		shex[ noffset ] = stmp[ 0 ];
		shex[ noffset + 1 ] = stmp[ 1 ];
		
		std::isprint( cstep ) ? sascii[ j ] = cstep : sascii[ j ] = '.';
		
		if ( ++j >= 16 )
		{
			snprintf( stmp, sizeof( stmp ), " %08d:", nline );
			outobj << stmp;
			nline += 16;

			outobj << shex;

			j = 0;
			outobj << "| " << sascii;

			if( i + j + 1 < nsize ) 
				outobj << "\n";
			memset( shex, ' ', 50 );
			memset( sascii, ' ', 16 );
		}
	}

	if ( j > 0 )
	{
		snprintf( stmp, sizeof( stmp ), " %08d:", nline );
		outobj << stmp;
		
		outobj << shex;
		outobj << "| " << sascii;
	}

	outobj << "\n+-----------------------------------------------------------------------------+\n";
}

