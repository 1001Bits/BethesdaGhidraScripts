#pragma once
#include <type_traits>
namespace spdlog {
  struct source_loc { const char* filename = nullptr; int line = 0; const char* funcname = nullptr; };
  class logger {};
  namespace level { enum level_enum { trace, debug, info, warn, err, critical, off }; }

  // CommonLibF4VR's F4SE/Logger.h names this in a deduction guide:
  //   template <class... Args>
  //   a_func(spdlog::format_string_t<Args...>, Args&&...) -> a_func<Args...>;
  //
  // Args must be deduced from the trailing pack, NOT from the format string, so
  // -- exactly as std::format_string does -- the alias routes them through
  // type_identity_t to make the first parameter a non-deduced context.  Without
  // that, every log call fails deduction.  This is a format string, never a
  // member of a game type, so nothing here can move a struct field.
  template<typename... Args> struct basic_format_string_t {
    template<typename T> constexpr basic_format_string_t(const T&) {}
  };
  template<typename... Args>
  using format_string_t = basic_format_string_t<std::type_identity_t<Args>...>;

  template<typename... Args> void log(level::level_enum, Args&&...) {}
  template<typename... Args> void log(source_loc, level::level_enum, Args&&...) {}
}
