// Parse-only shim for rapidcsv, included by CommonLibF4VR's REL/IDDB.h under
// ENABLE_FALLOUT_VR (it reads the VR address library from CSV rather than the
// binary .bin format).
//
// Safe to stub: the type is used only inside REL/IDDB.cpp -- which this parse
// never reads -- and no RE:: game struct has a rapidcsv member, so no extracted
// layout can shift because of it.  Same reasoning as _clang_stubs/mmio.
#pragma once
#include <cstddef>
#include <string>

namespace rapidcsv {
class Document {
public:
    Document() = default;
    template <typename... Args>
    explicit Document(Args&&...) {}

    template <typename T>
    T GetCell(std::size_t, std::size_t) const { return T{}; }
    [[nodiscard]] std::size_t GetRowCount() const { return 0; }
    [[nodiscard]] std::size_t GetColumnCount() const { return 0; }
};
}  // namespace rapidcsv
