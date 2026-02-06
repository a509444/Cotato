#include "log.h"

#include <cstdarg>
#include <cstdio>

static bool g_log_enabled = true;

static const char* kColorGreen = "\x1b[32m";
static const char* kColorRed = "\x1b[31m";
static const char* kColorReset = "\x1b[0m";

extern "C" {

void log_set_enabled(bool enabled)
{
    g_log_enabled = enabled;
}

bool log_is_enabled(void)
{
    return g_log_enabled;
}

void log_info(const char* message)
{
    if (!g_log_enabled || !message)
    {
        return;
    }
    std::fputs(kColorGreen, stdout);
    std::fputs(message, stdout);
    std::fputs(kColorReset, stdout);
    std::fputc('\n', stdout);
}

void log_error(const char* message)
{
    if (!g_log_enabled || !message)
    {
        return;
    }
    std::fputs(kColorRed, stderr);
    std::fputs(message, stderr);
    std::fputs(kColorReset, stderr);
    std::fputc('\n', stderr);
}

void log_infof(const char* format, ...)
{
    if (!g_log_enabled || !format)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    std::fputs(kColorGreen, stdout);
    std::vfprintf(stdout, format, args);
    std::fputs(kColorReset, stdout);
    std::fputc('\n', stdout);
    va_end(args);
}

void log_errorf(const char* format, ...)
{
    if (!g_log_enabled || !format)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    std::fputs(kColorRed, stderr);
    std::vfprintf(stderr, format, args);
    std::fputs(kColorReset, stderr);
    std::fputc('\n', stderr);
    va_end(args);
}

void log_info_w(const wchar_t* message)
{
    if (!g_log_enabled || !message)
    {
        return;
    }
    std::fputs(kColorGreen, stdout);
    std::fputws(message, stdout);
    std::fputs(kColorReset, stdout);
    std::fputwc(L'\n', stdout);
}

void log_error_w(const wchar_t* message)
{
    if (!g_log_enabled || !message)
    {
        return;
    }
    std::fputs(kColorRed, stderr);
    std::fputws(message, stderr);
    std::fputs(kColorReset, stderr);
    std::fputwc(L'\n', stderr);
}

void log_infof_w(const wchar_t* format, ...)
{
    if (!g_log_enabled || !format)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    std::fputs(kColorGreen, stdout);
    std::vfwprintf(stdout, format, args);
    std::fputs(kColorReset, stdout);
    std::fputwc(L'\n', stdout);
    va_end(args);
}

void log_errorf_w(const wchar_t* format, ...)
{
    if (!g_log_enabled || !format)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    std::fputs(kColorRed, stderr);
    std::vfwprintf(stderr, format, args);
    std::fputs(kColorReset, stderr);
    std::fputwc(L'\n', stderr);
    va_end(args);
}

void log_raw(const char* message)
{
    if (!g_log_enabled || !message)
    {
        return;
    }
    std::fputs(message, stdout);
}

void log_rawf(const char* format, ...)
{
    if (!g_log_enabled || !format)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    std::vfprintf(stdout, format, args);
    va_end(args);
}

} // extern "C"
