// Parse-only shim for Ryan-rsm-McKenzie/mmio, pulled in by CommonLibF4VR's
// F4SE/Impl/PCH.h.  Stubbing a header is only safe when its types cannot move a
// game struct's fields: mmio appears in exactly one place, REL/IDDB.h --
//
//     mmio::mapped_file_source _mmap;
//
// -- a member of CommonLib's own address-library database, never of an RE::
// game type.  No layout we extract can shift because of it.  (Contrast
// DirectXTK's SimpleMath, which RE/S/State.h holds *by value*: that one is
// vendored for real, because a wrong size there would silently shift every
// field after it.)
#pragma once
#include <cstddef>
#include <filesystem>

namespace mmio {
class mapped_file_source {
public:
    mapped_file_source() = default;
    template <typename T>
    explicit mapped_file_source(T&&) {}

    bool open(const std::filesystem::path&) { return false; }
    void close() {}
    [[nodiscard]] bool is_open() const { return false; }
    [[nodiscard]] const std::byte* data() const { return nullptr; }
    [[nodiscard]] std::size_t size() const { return 0; }
    explicit operator bool() const { return false; }
};
}  // namespace mmio
