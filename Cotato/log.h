#pragma once

#include <stdbool.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

void log_set_enabled(bool enabled);
bool log_is_enabled(void);

void log_info(const char* message);
void log_error(const char* message);
void log_infof(const char* format, ...);
void log_errorf(const char* format, ...);

void log_info_w(const wchar_t* message);
void log_error_w(const wchar_t* message);
void log_infof_w(const wchar_t* format, ...);
void log_errorf_w(const wchar_t* format, ...);
void log_raw(const char* message);
void log_rawf(const char* format, ...);

#ifdef __cplusplus
}

#include <sstream>
#include <string>

class LogStream
{
public:
    explicit LogStream(bool isError) : isError(isError) {}
    ~LogStream()
    {
        std::string msg = stream.str();
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
        {
            msg.pop_back();
        }
        if (msg.empty())
        {
            return;
        }
        if (isError)
        {
            log_error(msg.c_str());
        }
        else
        {
            log_info(msg.c_str());
        }
    }

    template <typename T>
    LogStream& operator<<(const T& value)
    {
        stream << value;
        return *this;
    }

    LogStream& operator<<(std::ostream& (*manip)(std::ostream&))
    {
        stream << manip;
        return *this;
    }

private:
    bool isError;
    std::ostringstream stream;
};

class LogStreamW
{
public:
    explicit LogStreamW(bool isError) : isError(isError) {}
    ~LogStreamW()
    {
        std::wstring msg = stream.str();
        while (!msg.empty() && (msg.back() == L'\n' || msg.back() == L'\r'))
        {
            msg.pop_back();
        }
        if (msg.empty())
        {
            return;
        }
        if (isError)
        {
            log_error_w(msg.c_str());
        }
        else
        {
            log_info_w(msg.c_str());
        }
    }

    template <typename T>
    LogStreamW& operator<<(const T& value)
    {
        stream << value;
        return *this;
    }

    LogStreamW& operator<<(std::wostream& (*manip)(std::wostream&))
    {
        stream << manip;
        return *this;
    }

private:
    bool isError;
    std::wostringstream stream;
};

#define LOG_INFO_STREAM LogStream(false)
#define LOG_ERROR_STREAM LogStream(true)
#define LOG_INFO_WSTREAM LogStreamW(false)
#define LOG_ERROR_WSTREAM LogStreamW(true)
#endif
