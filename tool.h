#ifndef _TOOLS_H_
#define _TOOLS_H_
#include <string>
#include <vector>       //vector

//执行cmd命令并获取输出的结果
int     app_call_popen( const char * cmd, std::string & sout );

//通过空格将字符串分隔成向量
size_t  str_split_delimeter( const std::string & strsrc, const char delimeter, std::vector<std::string> & vec_str );

//清除字符串中指定的子字符串
void str_clear_all( std::string & strsrc, const char * dirtychar );

//将长整理long转换为string字符串
void    str_from_ulong( unsigned long ulvalue, std::string & sout );

//字符串与hex的相互转换, 3DES加密时使用
size_t  str_to_hex( const std::string & sdata, std::string & shex, int lower_upper );
size_t  hex_to_str( const std::string & shex, std::string & sdata );

//阻塞式读取文件
int64_t file_block_read( const std::string & filename, std::string & sout );

//打印输出查看
void buffer_hex_print( const void * buffer, uint nsize, std::ostream & outobj, const char * title );

#define printerr(...) fprintf(stderr,__VA_ARGS__)
#endif