#include "../server.hpp"
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex>

#define DEFAULT_TIMEOUT 30

class Util
{
public:
    // 字符串分割,src按照sep进行分割放到array中,返回子串数量
    static size_t Split(const std::string& src, const std::string& sep, std::vector<std::string>* array)
    {
        size_t offset = 0;
        while(offset < src.size())
        {
            size_t pos = src.find(sep, offset); // TODO: find
            if(pos == std::string::npos) // TODO: npos
            {
                // 没找到特定字符,将剩余部分当子串
                if(pos == src.size()) break;
                array->emplace_back(src.substr(offset)); // TODO: substr
                return array->size();
            }
            if(pos == offset)
            {
                offset = pos + sep.size();
                continue;
            }
            array->emplace_back(src.substr(offset, pos - offset));
            offset = pos + sep.size();
        }
        return array->size();
    }
    // 读取文件所有内容放到Buffer // TODO: C++IO
    static bool ReadFile(const std::string& filename, std::string* buf)
    {
        std::ifstream ifs(filename, std::ios::binary);
        if(ifs.is_open() == false)
        {
            ERR_LOG("OPEN %s FAILED!", filename.c_str());
            return false;
        }

        size_t fsize = 0;
        ifs.seekg(0, ifs.end); // TODO: 跳转读写位置到末尾
        fsize = ifs.tellg(); // TODO: 获取当前读写位置相对于起始位置的偏移量
        ifs.seekg(0, ifs.beg);
        buf->resize(fsize);
        ifs.read(&(*buf)[0], fsize);
        if(ifs.good() == false)
        {
            ERR_LOG("READ %s FAILED!", filename.c_str());
            ifs.close();
            return false;
        }
        ifs.close();
        return true;
    }
    // 向文件写入数据
    static bool WriteFile(const std::string& filename, const std::string& buf)
    {
        std::ofstream ofs(filename, std::ios::binary | std::ios::trunc); // TODO: trunc
        if(ofs.is_open() == false)
        {
            ERR_LOG("OPEN %s FAILED!", filename.c_str());
            return false;
        }
        ofs.write(buf.c_str(), buf.size());
        if(ofs.good() == false)
        {
            ERR_LOG("WRITE %s FAILED!", filename.c_str());
            ofs.close();
            return false;
        }
        ofs.close();
        return true;
    }
    // URL编码，避免URL中资源路径与查询字符串中的特殊字符与HTTP请求中特殊字符产生歧义
    // 编码格式：将特殊字符的ascii值，转换为两个16进制字符，前缀% C++ -> C%2B%2B
    // 不编码的特殊字符： RFC3986文档规定.-_~字母，数字属于绝对不编码字符
    // RFC3986文档规定，编码格式 %HH
    // W3C标准中规定，查询字符串中的空格，需要编码为+， 解码则是+转空格
    static std::string UrlEncode(const std::string& url, bool convert_space_to_plus)
    {
        std::string ret;
        for(auto& c : url)
        {
            if(c == '.' || c == '-' || c == '_' || c == '~' || isalnum(c))
            {
                ret += c;
                continue;
            }
            if(c == ' ' && convert_space_to_plus)
            {
                ret += '+';
                continue;
            }
            // 剩下的字符都需要转换为 %HH 格式
            char tmp[4] = {0};
            snprintf(tmp, 4, "%%%02X", c); // TODO: snprintf
            ret += tmp;
        }
        return ret;
    }
    // URL解码
    static char HextoI(char c)
    {
        if(c >= '0' && c <= '9') return c - '0';
        else if(c >= 'a' && c <= 'z') return c - 'a';
        else if(c >= 'A' && c <= 'Z') return c - 'A';
        return -1;
    }
    static std::string UrlDecode(const std::string& url, bool convert_plus_to_space)
    {
        // 遇到了%其后的两个字符转换为数字，第一个字符左移4位(乘16)加上第二个数字
        std::string ret;
        for(int i = 0; i < url.size(); i++)
        {
            if(url[i] == '%')
            {
                char v1 = HextoI(url[i + 1]);
                char v2 = HextoI(url[i + 2]);
                char v = (v1 << 4) + v2;
                i += 2;
                continue;
            }
            ret += url[i];
        }
        return ret;
    }
    // 响应状态码的描述信息获取
    static std::string StatusDesc(int status)
    {
        std::unordered_map<int, std::string> _status_msg = {
            {100,  "Continue"},
            {101,  "Switching Protocol"},
            {102,  "Processing"},
            {103,  "Early Hints"},
            {200,  "OK"},
            {201,  "Created"},
            {202,  "Accepted"},
            {203,  "Non-Authoritative Information"},
            {204,  "No Content"},
            {205,  "Reset Content"},
            {206,  "Partial Content"},
            {207,  "Multi-Status"},
            {208,  "Already Reported"},
            {226,  "IM Used"},
            {300,  "Multiple Choice"},
            {301,  "Moved Permanently"},
            {302,  "Found"},
            {303,  "See Other"},
            {304,  "Not Modified"},
            {305,  "Use Proxy"},
            {306,  "unused"},
            {307,  "Temporary Redirect"},
            {308,  "Permanent Redirect"},
            {400,  "Bad Request"},
            {401,  "Unauthorized"},
            {402,  "Payment Required"},
            {403,  "Forbidden"},
            {404,  "Not Found"},
            {405,  "Method Not Allowed"},
            {406,  "Not Acceptable"},
            {407,  "Proxy Authentication Required"},
            {408,  "Request Timeout"},
            {409,  "Conflict"},
            {410,  "Gone"},
            {411,  "Length Required"},
            {412,  "Precondition Failed"},
            {413,  "Payload Too Large"},
            {414,  "URI Too Long"},
            {415,  "Unsupported Media Type"},
            {416,  "Range Not Satisfiable"},
            {417,  "Expectation Failed"},
            {418,  "I'm a teapot"},
            {421,  "Misdirected Request"},
            {422,  "Unprocessable Entity"},
            {423,  "Locked"},
            {424,  "Failed Dependency"},
            {425,  "Too Early"},
            {426,  "Upgrade Required"},
            {428,  "Precondition Required"},
            {429,  "Too Many Requests"},
            {431,  "Request Header Fields Too Large"},
            {451,  "Unavailable For Legal Reasons"},
            {501,  "Not Implemented"},
            {502,  "Bad Gateway"},
            {503,  "Service Unavailable"},
            {504,  "Gateway Timeout"},
            {505,  "HTTP Version Not Supported"},
            {506,  "Variant Also Negotiates"},
            {507,  "Insufficient Storage"},
            {508,  "Loop Detected"},
            {510,  "Not Extended"},
            {511,  "Network Authentication Required"}
        };
        auto it = _status_msg.find(status);
        if(it == _status_msg.end()) return "UnKnown";
        return it->second;
    }
    // 根据文件后缀名获取文件mime // TODO: mime
    static std::string ExtMime(const std::string& filename)
    {
        std::unordered_map<std::string, std::string> _mime_desc = {
            {".aac",        "audio/aac"},
            {".abw",        "application/x-abiword"},
            {".arc",        "application/x-freearc"},
            {".avi",        "video/x-msvideo"},
            {".azw",        "application/vnd.amazon.ebook"},
            {".bin",        "application/octet-stream"},
            {".bmp",        "image/bmp"},
            {".bz",         "application/x-bzip"},
            {".bz2",        "application/x-bzip2"},
            {".csh",        "application/x-csh"},
            {".css",        "text/css"},
            {".csv",        "text/csv"},
            {".doc",        "application/msword"},
            {".docx",       "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            {".eot",        "application/vnd.ms-fontobject"},
            {".epub",       "application/epub+zip"},
            {".gif",        "image/gif"},
            {".htm",        "text/html"},
            {".html",       "text/html"},
            {".ico",        "image/vnd.microsoft.icon"},
            {".ics",        "text/calendar"},
            {".jar",        "application/java-archive"},
            {".jpeg",       "image/jpeg"},
            {".jpg",        "image/jpeg"},
            {".js",         "text/javascript"},
            {".json",       "application/json"},
            {".jsonld",     "application/ld+json"},
            {".mid",        "audio/midi"},
            {".midi",       "audio/x-midi"},
            {".mjs",        "text/javascript"},
            {".mp3",        "audio/mpeg"},
            {".mpeg",       "video/mpeg"},
            {".mpkg",       "application/vnd.apple.installer+xml"},
            {".odp",        "application/vnd.oasis.opendocument.presentation"},
            {".ods",        "application/vnd.oasis.opendocument.spreadsheet"},
            {".odt",        "application/vnd.oasis.opendocument.text"},
            {".oga",        "audio/ogg"},
            {".ogv",        "video/ogg"},
            {".ogx",        "application/ogg"},
            {".otf",        "font/otf"},
            {".png",        "image/png"},
            {".pdf",        "application/pdf"},
            {".ppt",        "application/vnd.ms-powerpoint"},
            {".pptx",       "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
            {".rar",        "application/x-rar-compressed"},
            {".rtf",        "application/rtf"},
            {".sh",         "application/x-sh"},
            {".svg",        "image/svg+xml"},
            {".swf",        "application/x-shockwave-flash"},
            {".tar",        "application/x-tar"},
            {".tif",        "image/tiff"},
            {".tiff",       "image/tiff"},
            {".ttf",        "font/ttf"},
            {".txt",        "text/plain"},
            {".vsd",        "application/vnd.visio"},
            {".wav",        "audio/wav"},
            {".weba",       "audio/webm"},
            {".webm",       "video/webm"},
            {".webp",       "image/webp"},
            {".woff",       "font/woff"},
            {".woff2",      "font/woff2"},
            {".xhtml",      "application/xhtml+xml"},
            {".xls",        "application/vnd.ms-excel"},
            {".xlsx",       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
            {".xml",        "application/xml"},
            {".xul",        "application/vnd.mozilla.xul+xml"},
            {".zip",        "application/zip"},
            {".3gp",        "video/3gpp"},
            {".3g2",        "video/3gpp2"},
            {".7z",         "application/x-7z-compressed"}
        };

        size_t pos = filename.find_last_of('.');
        if(pos == std::string::npos) return "application/octet-stream"; // 文件为二进制流
        
        std::string tmp = filename.substr(pos);
        auto it = _mime_desc.find(tmp);
        if(it == _mime_desc.end()) return "application/octet-stream";
        return it->second;
    }
    // 判断一个文件是否是目录
    static bool IsDirectory(const std::string& filename)
    {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if(ret < 0)
        {
            ERR_LOG("GET STAT FAILED!");
            return false;
        }
        return S_ISDIR(st.st_mode); // TODO: S_ISDIR  st_mode
    }
    // 判断一个文件是否是普通文件
    static bool IsRegular(const std::string& filename)
    {
        struct stat st;
        int ret = stat(filename.c_str(), &st);
        if(ret < 0)
        {
            ERR_LOG("GET STAT FAILED!");
            return false;
        }
        return S_ISREG(st.st_mode); // TODO: S_ISREG  st_mode
    }
    // 判断http请求资源路径有效性
    // /index.html -- 前边的/叫做相对根目录 映射的是某个服务器上的子目录
    // 想表达的意思就是，客户端只能请求相对根目录中的资源，其他地方的资源都不予理会
    // ./../login，这个路径中的 .. 会让路径的查找跑到相对根目录之外，这是不合理的，不安全的
    static bool ValidPath(const std::string& path)
    {
        //思想：按照/进行路径分割，根据有多少子目录，计算目录深度，有多少层，深度不能小于0
        std::vector<std::string> subdir;
        Split(path, "/", &subdir);
        int level = 0; // ./算第0层
        for(auto& dir : subdir)
        {
            if(dir == "..")
            {
                level--;
                if(level < 0) return false;
                continue;
            }
            level++;
        }
        return true;
    }
};

class HttpRequest
{
public:
    std::string _method; // 请求方法
    std::string _path; // 资源路径
    std::string _version; // 协议版本
    std::string _body; // 请求正文
    std::smatch _matches; // 资源路径的正则提取数据
    std::unordered_map<std::string, std::string> _headers; // 头部字段
    std::unordered_map<std::string, std::string> _parameters; // 查询字符串
public:
    HttpRequest() : _version("HTTP/1.1") {};
    //
    void ReSet()
    {
        _method.clear(); // TODO: clear
        _path.clear();
        _version = "HTTP/1.1"; // TODO: ?有的地方会用到此数据，但是是先获取再用，可能获取失败，最好初始化?
        _body.clear();
        std::smatch sm;
        _matches.swap(sm);
        _headers.clear();
        _parameters.clear();
    }
    // 插入头部字段
    void SetHeader(const std::string& key, const std::string& val) { _headers.insert(std::make_pair(key, val)); }
    // 判断是否存在指定头部字段
    bool HasHeader(const std::string& key) const
    {
        auto it = _headers.find(key);
        if(it == _headers.end()) return false;
        return true;
    }
    // 获取指定头部字段的值
    std::string GetHeader(const std::string& key) const
    {
        // if(_headers.count(key)) return _headers[key];
        // return "";
        auto it = _headers.find(key);
        if(it == _headers.end()) return "";
        return it->second;
    }
    // 插入查询字符串
    void SetParam(const std::string& key, const std::string& val) { _parameters.insert(std::make_pair(key, val)); }
    // 判断是否有某个指定的查询字符串
    bool HasParam(const std::string& key)
    {
        auto it = _parameters.find(key);
        if(it == _parameters.end()) return false;
        return true;
    }
    // 获取指定的查询字符串
    std::string GetParam(const std::string& key)
    {
        auto it = _parameters.find(key);
        if(it == _parameters.end()) return "";
        return it->second;
    }
    // 获取正文长度
    size_t ContentLength()
    {
        bool ret = HasHeader("Content-Length");
        if(ret == false) return 0;
        std::string clen = GetHeader("Content-Length");
        return std::stol(clen); // TODO: stol
    }
    // 判断是否是短链接 TODO
    bool Close() const
    {
        // 没有Connection字段或者值为close，就是短连接
        bool ret = HasHeader("Connection");
        if(ret == false || GetHeader("Connection") == "close") return true;
        return false;
    }
};

class HttpResponse
{
public:
    int _status;
    std::string _body;
    bool _redirect_flag;
    std::string _redirect_url;
    std::unordered_map<std::string, std::string> _headers;
public:
    HttpResponse()
        : _status(200)
        , _redirect_flag(false)
    {}
    HttpResponse(int status)
        : _status(status)
        , _redirect_flag(false)
    {}

    void ReSet()
    {
        _status = 200;
        _body.clear();
        _redirect_flag = false;
        _redirect_url.clear();
        _headers.clear();
    }
    void SetHeader(const std::string& key, const std::string& val) { _headers.insert(std::make_pair(key, val)); }
    bool HasHeader(const std::string& key)
    {
        auto it = _headers.find(key);
        if(it == _headers.end()) return false;
        return true;
    }
    std::string GetHeader(const std::string& key)
    {
        auto it = _headers.find(key);
        if(it == _headers.end()) return "";
        return it->second;
    }
    void SetContent(const std::string& body, const std::string& type)
    {
        _body = body;
        SetHeader("Content-Type", type);
    }
    // TODO: status302
    void SetRedirect(const std::string& url, int status = 302)
    {
        _status = status;
        _redirect_flag = true;
        _redirect_url = url;
    }
    bool Close()
    {
        bool ret = HasHeader("Connection");
        if(ret == false || GetHeader("Connection") == "close") return true;
        return false;
    }
};

typedef enum
{
    RECV_HTTP_ERROR,
    RECV_HTTP_LINE,
    RECV_HTTP_HEAD,
    RECV_HTTP_BODY,
    RECV_HTTP_OVER
}HttpRecvStatus;

#define MAXLINE 8192
class HttpContext
{
private:
    bool RecvHttpLine(Buffer* buf)
    {
        if(_recv_status != RECV_HTTP_LINE) return false;
        // 1、获取一行数据
        std::string line = buf->GetLineAndPop();
        // 2、缓冲区数据不足一行或获取一行的数据超大
        if(line.size() == 0) // TODO: ==0? 缓冲区没读出来?
        {
            if(buf->GetReadableSize() > MAXLINE)
            {
                _recv_status = RECV_HTTP_ERROR;
                _resp_status = 414; // 414: URI too long TODO:URL and URI
                return false;
            }
            // 缓冲区数据不足一行，但是也不多，就等新数据到来
            return true;
        }
        if(line.size() > MAXLINE)
        {
            _recv_status = RECV_HTTP_ERROR;
            _resp_status = 414; // 414: URI too long TODO:URL and URI
            return false;
        }
        bool ret = ParseHttpLine(line);
        if(ret == false) return false;
        _recv_status = RECV_HTTP_HEAD;
        return true;
    }
    bool ParseHttpLine(const std::string& line)
    {
        std::smatch matches;
        std::regex e("(GET|HEAD|POST|PUT|DELETE) ([^?]*)(?:\\?(.*))? (HTTP/1\\.[01])(?:\n|\r\n)?", std::regex::icase); // std::regex::icase忽略大小写
        bool ret = std::regex_match(line, matches, e);
        if(ret == false)
        {
            _recv_status = RECV_HTTP_ERROR;
            _resp_status = 400; // BAD REQUEST
            return false;
        }
        // TODO: 各个部分对应什么
        // 0: GET /bilibili/login?user=Jiasty&passwd=123456 HTTP/1.1
        // 1: GET
        // 2: /bilibili/login
        // 3: user=Jiasty&passwd=123456
        // 4: HTTP/1.1
        _request._method = matches[1];
        // 保证请求方法为大写
        std::transform(_request._method.begin(), _request._method.end(), _request._method.begin(), ::toupper); // TODO: transform and ::toupper
        // 资源路径获取，需要解码，但不需要+号转空格
        _request._path = Util::UrlDecode(matches[2], false); // TODO: why UrlDecode且false?
        _request._version = matches[4];
        std::vector<std::string> querry_string_array;
        std::string querry_string = matches[3];
        Util::Split(querry_string, "&", &querry_string_array);
        for(auto& str : querry_string_array)
        {
            size_t pos = str.find("=");
            if(pos == std::string::npos) // TODO: VS .end()
            {
                _recv_status = RECV_HTTP_ERROR;
                _resp_status = 400; // BAD REQUEST
                return false;
            }
            std::string key = Util::UrlDecode(str.substr(0, pos), true);
            std::string val = Util::UrlDecode(str.substr(pos + 1), true);
            _request.SetParam(key, val);
        }
        return true;
    }
    bool RecvHttpHead(Buffer* buf)
    {
        if(_recv_status != RECV_HTTP_HEAD) return false;
        while(1)
        {
            // 1、获取一行数据
            std::string line = buf->GetLineAndPop();
            // 2、缓冲区数据不足一行或获取一行的数据超大
            if(line.size() == 0) // TODO: ==0? 缓冲区没读出来?
            {
                if(buf->GetReadableSize() > MAXLINE)
                {
                    _recv_status = RECV_HTTP_ERROR;
                    _resp_status = 414; // 414: URI too long TODO:URL and URI
                    return false;
                }
                // 缓冲区数据不足一行，但是也不多，就等新数据到来
                return true;
            }
            if(line.size() > MAXLINE)
            {
                _recv_status = RECV_HTTP_ERROR;
                _resp_status = 414; // 414: URI too long TODO:URL and URI
                return false;
            }
            if(line == "\n" || line == "\r\n") break; // 遇到空行则头部解析完成
            bool ret = ParseHttpHead(line);
            if(ret == false) return false;
        }
        _recv_status = RECV_HTTP_BODY;
        return true;
    }
    bool ParseHttpHead(const std::string& line)
    {
        size_t pos = line.find(": ");
        if(pos == std::string::npos)
        {
            _recv_status = RECV_HTTP_ERROR;
            _resp_status = 400; // BAD REQUEST
            return false;
        }
        std::string key = Util::UrlDecode(line.substr(0, pos), true);
        std::string val = Util::UrlDecode(line.substr(pos + 2), true);
        _request.SetHeader(key, val);
        return true;
    }
    bool RecvHttpBody(Buffer* buf)
    {
        if(_recv_status != RECV_HTTP_BODY) return false;
        // 1、获取正文长度
        size_t content_length = _request.ContentLength();
        if(content_length == 0)
        {
            _recv_status = RECV_HTTP_OVER;
            return true;
        }
        // 2、当前保存了多少正文 _request._body中
        size_t to_accept_lenght = content_length - _request._body.size(); // 还需接收的
        // 3、接收剩下的正文，考虑当前缓冲区中的数据是否是全部的正文
        //   3.1、缓冲区中的数据，包含了当前请求的所有正文，取出数据
        if(buf->GetReadableSize() >= to_accept_lenght)
        {
            _request._body.append(buf->GetReadPosition(), to_accept_lenght);
            buf->MoveReadPosition(to_accept_lenght);
            _recv_status = RECV_HTTP_OVER;
            return true;
        }
        //   3.2、缓冲区中的数据，无法满足当前正文的需求，数据不足，取出数据，等待新数据到来
        _request._body.append(buf->GetReadPosition(), buf->GetReadableSize());
        buf->MoveReadPosition(buf->GetReadableSize());
        return true;
    }
public:
    HttpContext()
        : _resp_status(200)
        , _recv_status(RECV_HTTP_LINE)
    {}
    void ReSet()
    {
        _resp_status = 200;
        _recv_status = RECV_HTTP_LINE;
        _request.ReSet();
    }
    int RespStatus() { return _resp_status; }
    HttpRecvStatus RecvStatus() { return _recv_status; }
    HttpRequest& Request() { return _request; }
    // 接收并解析HTTP请求
    void RecvHttpRequest(Buffer* buf)
    {
        // 不同的状态，做不同的事情，但是这不要break，应顺序依次执行
        switch(_resp_status)
        {
            case RECV_HTTP_LINE : RecvHttpLine(buf);
            case RECV_HTTP_HEAD : RecvHttpHead(buf);
            case RECV_HTTP_BODY : RecvHttpBody(buf);
        }
    }
private:
    int _resp_status; // 响应状态码
    HttpRecvStatus _recv_status; // 当前接收及解析的阶段状态
    HttpRequest _request; // 已经解析得到的请求信息
};

using Handler = std::function<void(const HttpRequest&, HttpResponse*)>;
using Handlers = std::vector<std::pair<std::regex, Handler>>;
class HttpServer
{
private:
    void ErrorHandler(const HttpRequest& request, HttpResponse* respons)
    {
        // 1、组织一个错误展示页面
        std::string body("<html><head><meta http-equiv='Content-Type' content = 'text/html;cahrset=utf-8'></head><body><h1>" + std::to_string(respons->_status) + " " + Util::StatusDesc(respons->_status) + "</h1></body></html>");
        // 2、将页面数据当作响应正文放入response
        respons->SetContent(body, "text/html");
    }
    // 将HttpResponse中的要素按照http协议格式进行组织，发送
    void onse(const ConnectionPtr& conn, const HttpRequest& request, HttpResponse& response)
    {
        // 1、先完善头部字段
        if(request.Close()) response.SetHeader("Connection", "close");
        else response.SetHeader("Connection", "keep-alive");

        if(response._body.empty() == false && response.HasHeader("Content-Length") == false) response.SetHeader("Content-Length", std::to_string(response._body.size()));
        if(response._body.empty() == false && response.HasHeader("Content-Type") == false) response.SetHeader("Content-Type", "application/octet-stream"); // TODO: application/octet-stream

        if(response._redirect_flag) response.SetHeader("Location", response._redirect_url);
        // 2、将response中的要素，按照http协议格式进行组织
        std::stringstream resp_str;
        resp_str << request._version << " " << std::to_string(response._status) << " " << Util::StatusDesc(response._status) << "\r\n";
        for(auto& head : response._headers) resp_str << head.first << ": " << head.second << "\r\n"; // TODO: "\r\n"
        resp_str << "\r\n";
        resp_str << response._body;
        // 3、发送数据
        conn->Send(resp_str.str().c_str(), resp_str.str().size()); // TODO: resp_str.str()
    }
    // 判断是否是静态资源请求
    bool IsFileHandler(const HttpRequest& request)
    {
        // 1、必须设置了静态资源根目录
        if(_basedir.empty()) return false;
        // 2、请求方法必须是 GET HEAD
        if(request._method != "GET" && request._method != "HEAD") return false;
        // 3、必须是一个合法路径
        if(Util::ValidPath(request._path) == false) return false;
        // 4、请求的资源必须存在,且是一个普通文件
        //    特殊的请求，纯粹的目录: /，/image/，这种情况给后面默认追加一个index.html
        std::string req_path = _basedir + request._path; // 避免直接修改资源路径
        if(request._path.back() == '/') req_path += "index.html";
        if(Util::IsRegular(req_path) == false) return false;
        return true;
    }
    // 静态资源请求处理 -- 将静态资源文件的数据读取出来放到response的_body中，并设置MIME
    void FileHandler(const HttpRequest& request, HttpResponse* response)
    {
        std::string req_path = _basedir + request._path; // 避免直接修改资源路径
        if(request._path.back() == '/') req_path += "index.html";
        bool ret = Util::ReadFile(req_path, &response->_body);
        if(ret == false) return;
        std::string mime = Util::ExtMime(req_path);
        response->SetHeader("Content-Type", mime);
    }
    // 功能性请求分类处理
    void Dispatcher(HttpRequest& request, HttpResponse* response, Handlers& handlers)// TODO
    {
        // 在对应请求方法的路由表中，查找是否含有对应资源请求的处理函数，有则调用，没有则发回404
        // 思想:路由表存储的键值对 -- 正则表达式 & 处理函数
        // 使用正则表达式对请求的资源路径进行正则匹配，匹配成功就使用对应函数进行处理
        for(auto& handler : handlers)
        {
            std::regex& re = handler.first;
            Handler& functor = handler.second;
            bool ret = std::regex_match(request._path, request._matches, re); // 涉及对request的修改
            if(ret == false) continue;
            return functor(request, response);
        }
    }
    void Route(HttpRequest& request, HttpResponse* response)
    {
        // 1、对请求进行分辨，是一个静态资源请求还是功能性请求
        //    静态资源请求，则进行静态资源处理
        //    功能性请求，则需要通过几个请求路由表来确定是否有处理函数
        //    都不是则返回405
        if(IsFileHandler(request)) return FileHandler(request, response);
        if(request._method == "GET" || request._method == "HEAD") return Dispatcher(request, response, _get_route);
        else if(request._method == "POST") return Dispatcher(request, response, _post_route);
        else if(request._method == "PUT") return Dispatcher(request, response, _put_route);
        else if(request._method == "DELETE") return Dispatcher(request, response, _delete_route);

        response->_status = 405; // Method Not Allowed
    }
    // 设置上下文
    void OnCnnected(const ConnectionPtr& conn)
    {
        conn->SetContext(HttpContext());
        DBG_LOG("NEW CONNECTION %p", conn.get());
    }
    // 缓冲区数据解析+处理
    void OnMessage(const ConnectionPtr& conn, Buffer* buf)
    {
        while(buf->GetReadableSize())
        {
            // 1、获取上下文
            HttpContext* context = conn->GetContext()->Get<HttpContext>();
            // 2、通过上下文对缓冲区数据进行解析，得到HttpRequest对象
            //    1) 如果缓冲区的数据解析出错，就直接回复出错响应
            //    2) 如果解析正常，且请求已经获取完毕，才开始去进行处理
            context->RecvHttpRequest(buf);
            HttpRequest& request = context->Request();
            HttpResponse response(context->RespStatus());
            if(context->RespStatus() >= 400) // TODO: >=400?
            {
                // 进行错误响应，关闭连接
                ErrorHandler(request, &response);
                WriteResponse(conn, request, response);
                conn->Shutdown();
                return; 
            }
            // 当前请求还未接收完整
            if(context->RecvStatus() != RECV_HTTP_OVER) return;
            
            
            // 3、请求路由 + 业务处理
            Route(request, &response);
            // 4、对HttpResponse进行组织发送
            WriteResponse(conn, request, response);
            // 5、重置上下文
            context->ReSet();
            // 6、根据长短连接判断是否关闭连接
            if(response.Close() == true) conn->Shutdown(); // TODO: Close在哪看?
        }
    }

public:
    HttpServer(int port, int timeout = DEFAULT_TIMEOUT)
        : _server(port)
    {
        _server.EnableInactiveRelease(30);
        _server.SetConnectedCallBack(std::bind(&HttpServer::OnCnnected, this, std::placeholders::_1));  // TODO: std::placeholders::_1
        _server.SetMessageCallBack(std::bind(&HttpServer::OnMessage, this, std::placeholders::_1, std::placeholders::_2));
    }
    void SetBaseDir(const std::string& path) { _basedir = path; }
    void SetGet(const std::string& pattern, Handler& handler) { _get_route.emplace_back(std::make_pair(std::regex(pattern), handler)); }
    void SetPost(const std::string& pattern, Handler& handler) { _post_route.emplace_back(std::make_pair(std::regex(pattern), handler)); }
    void SetPut(const std::string& pattern, Handler& handler) { _put_route.emplace_back(std::make_pair(std::regex(pattern), handler)); }
    void SetDelete(const std::string& pattern, Handler& handler) { _delete_route.emplace_back(std::make_pair(std::regex(pattern), handler)); }
    void SetThreadCount(int count) { _server.SetThreadCount(count); }
    void Listen() { _server.Start(); }
private:
    Handlers _get_route;
    Handlers _post_route;
    Handlers _put_route;
    Handlers _delete_route;
    std::string _basedir; // 静态资源根目录
    TcpServer _server;
};