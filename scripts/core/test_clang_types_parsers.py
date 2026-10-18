"""Regression tests for the pure clang-output parsers in ``clang_types``.

Every fixture below is text printed by the pinned clang 20.1.8 (trimmed of
``DefinitionData`` / implicit-member noise, addresses shortened), fed directly
to the parsing functions -- no clang process is needed.  Item numbers (T1..T18)
refer to the 2026-09-21 generator audit.
"""

import os
import sys

_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _CORE_DIR)

import clang_types  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# i686, everything at global scope (the xNVSE / FNV shape):
#   typedef unsigned int UInt32;
#   struct Base { virtual ~Base(); virtual void A(UInt32 id); };
#   struct Der : Base { virtual ~Der(); virtual void B(); };
#   enum class E1 : int { a }; enum E2 { b, c = 4 };
# clang prints ``game/d.h`` once; every later node only has line:/col: offsets.
AST_GLOBAL_X86 = r"""TranslationUnitDecl 0x6c90 <<invalid sloc>> <invalid sloc>
|-TypedefDecl 0x12a8 <game/d.h:1:1, col:22> col:22 referenced UInt32 'unsigned int'
| `-BuiltinType 0x6e40 'unsigned int'
|-CXXRecordDecl 0x1308 <line:2:1, col:59> col:8 referenced struct Base definition
| |-CXXRecordDecl 0x1440 <col:1, col:8> col:8 implicit referenced struct Base
| |-CXXDestructorDecl 0x15e8 <col:15, col:29> col:23 ~Base 'void () __attribute__((thiscall)) noexcept' virtual
| |-CXXMethodDecl 0x18a8 <col:32, col:56> col:45 A 'void (UInt32) __attribute__((thiscall))' virtual
| | `-ParmVarDecl 0x1778 <col:47, col:54> col:54 id 'UInt32':'unsigned int'
| `-CXXConstructorDecl 0x3770 <col:8> col:8 implicit constexpr Base 'void (const Base &) __attribute__((thiscall))' inline default noexcept-unevaluated 0x3770
|   `-ParmVarDecl 0x38a8 <col:8> col:8 'const Base &'
|-CXXRecordDecl 0x1c00 <line:3:1, col:55> col:8 struct Der definition
| |-public 'Base'
| |-CXXRecordDecl 0x1d80 <col:1, col:8> col:8 implicit referenced struct Der
| |-CXXDestructorDecl 0x1ef0 <col:21, col:34> col:29 ~Der 'void () __attribute__((thiscall)) noexcept' virtual
| | `-Overrides: [ 0x15e8 Base::~Base 'void () __attribute__((thiscall)) noexcept' ]
| |-CXXMethodDecl 0x2060 <col:37, col:52> col:50 B 'void () __attribute__((thiscall))' virtual
| |-CXXConstructorDecl 0x21a0 <col:8> col:8 implicit constexpr Der 'void (const Der &) __attribute__((thiscall))' inline default noexcept-unevaluated 0x21a0
| | `-ParmVarDecl 0x36d8 <col:8> col:8 'const Der &'
|-EnumDecl 0x3b80 <line:4:1, col:25> col:12 class E1 'int'
| `-EnumConstantDecl 0x3c68 <col:23> col:23 a 'E1'
`-EnumDecl 0x3cc8 <col:28, col:47> col:33 E2
  |-EnumConstantDecl 0x3da8 <col:38> col:38 b 'E2'
  `-EnumConstantDecl 0x3e50 <col:41, col:45> col:41 c 'E2'
    `-ConstantExpr 0x3e28 <col:45> 'int'
      |-value: Int 4
      `-IntegerLiteral 0x3e00 <col:45> 'int' 4
"""

# x86_64:
#   namespace RE {
#     void FreeFn(int);
#     template <class T> struct Tmpl {
#       enum class TE : int { kT0 = 40, kT1, kNeg = -2, kParen = (9) };
#       enum Dep { kD = sizeof(T), kE };
#       virtual void TM(T); void Plain(T); T v; };
#     struct UsesT { Tmpl<int> a; };
#     struct X { virtual void XV(); void L() { auto f = [](int) { return 1; }; } int x; };
#     inline void X::XV() {}
#   }
AST_TEMPLATE_X64 = r"""TranslationUnitDecl 0x6c90 <<invalid sloc>> <invalid sloc>
`-NamespaceDecl 0xda40 <RE/t.h:1:1, line:11:1> line:1:11 RE
  |-FunctionDecl 0xdbd8 <line:2:3, col:18> col:8 FreeFn 'void (int)'
  | `-ParmVarDecl 0xdae8 <col:15> col:18 'int'
  |-ClassTemplateDecl 0xde38 <line:3:3, line:7:3> line:3:29 Tmpl
  | |-TemplateTypeParmDecl 0xdca8 <col:13, col:19> col:19 referenced class depth 0 index 0 T
  | |-CXXRecordDecl 0xdd88 <col:22, line:7:3> line:3:29 struct Tmpl definition
  | | |-CXXRecordDecl 0xe0f0 <col:22, col:29> col:29 implicit struct Tmpl
  | | |-EnumDecl 0xe1b8 <line:4:5, col:66> col:16 class TE 'int'
  | | | |-EnumConstantDecl 0xe2c0 <col:27, col:33> col:27 kT0 'RE::Tmpl::TE'
  | | | | `-IntegerLiteral 0xe290 <col:33> 'int' 40
  | | | |-EnumConstantDecl 0xe320 <col:37> col:37 kT1 'RE::Tmpl::TE'
  | | | |-EnumConstantDecl 0xe3c0 <col:42, col:50> col:42 kNeg 'RE::Tmpl::TE'
  | | | | `-UnaryOperator 0xe3a0 <col:49, col:50> 'int' prefix '-'
  | | | |   `-IntegerLiteral 0xe378 <col:50> 'int' 2
  | | | `-EnumConstantDecl 0xe468 <col:53, col:64> col:53 kParen 'RE::Tmpl::TE'
  | | |   `-ParenExpr 0xe440 <col:62, col:64> 'int'
  | | |     `-IntegerLiteral 0xe418 <col:63> 'int' 9
  | | |-EnumDecl 0xe4c8 <line:5:5, col:35> col:10 Dep
  | | | |-EnumConstantDecl 0xe5d8 <col:16, col:29> col:16 kD 'RE::Tmpl::Dep'
  | | | | `-UnaryExprOrTypeTraitExpr 0xe5b0 <col:21, col:29> 'unsigned long long' sizeof 'T'
  | | | `-EnumConstantDecl 0xe638 <col:32> col:32 kE 'RE::Tmpl::Dep'
  | | |-CXXMethodDecl 0x6c90 <line:6:5, col:22> col:18 TM 'void (T)' virtual
  | | | `-ParmVarDecl 0xe6a8 <col:21> col:22 'T'
  | | |-CXXMethodDecl 0x6e28 <col:25, col:37> col:30 Plain 'void (T)'
  | | | `-ParmVarDecl 0x6d70 <col:36> col:37 'T'
  | | `-FieldDecl 0x6f08 <col:40, col:42> col:42 v 'T'
  | `-ClassTemplateSpecializationDecl 0x7188 <line:3:3, line:7:3> line:3:29 struct Tmpl definition implicit_instantiation
  |   |-TemplateArgument type 'int'
  |   | `-BuiltinType 0x6da0 'int'
  |   |-CXXRecordDecl 0x73e0 <col:22, col:29> col:29 implicit struct Tmpl
  |   |-EnumDecl 0x7490 <line:4:5, col:21> col:16 class TE 'int'
  |   |-EnumDecl 0x7588 <line:5:5, col:10> col:10 Dep
  |   | |-EnumConstantDecl 0x76f8 <col:16, col:29> col:16 kD 'RE::Tmpl<int>::Dep'
  |   | | `-ImplicitCastExpr 0x77b0 <col:21, col:29> 'unsigned int' <IntegralCast>
  |   | |   `-ConstantExpr 0x76d0 <col:21, col:29> 'unsigned long long'
  |   | |     |-value: Int 4
  |   | |     `-UnaryExprOrTypeTraitExpr 0x76b0 <col:21, col:29> 'unsigned long long' sizeof 'int'
  |   | `-EnumConstantDecl 0x7758 <col:32> col:32 kE 'RE::Tmpl<int>::Dep'
  |   |-CXXMethodDecl 0x78f8 <line:6:5, col:22> col:18 TM 'void (int)' implicit_instantiation virtual instantiated_from 0x6c90
  |   | `-ParmVarDecl 0x7818 <col:21> col:22 'int'
  |   |-CXXMethodDecl 0x7a70 <col:25, col:37> col:30 Plain 'void (int)' implicit_instantiation instantiated_from 0x6e28
  |   | `-ParmVarDecl 0x79d0 <col:36> col:37 'int'
  |   |-FieldDecl 0x7b48 <col:40, col:42> col:42 v 'int'
  |   `-CXXDestructorDecl 0x82b8 <col:29> col:29 implicit constexpr ~Tmpl 'void ()' inline default trivial noexcept-unevaluated 0x82b8
  |-CXXRecordDecl 0x6f80 <line:8:3, col:31> col:10 struct UsesT definition
  | |-CXXRecordDecl 0x70c0 <col:3, col:10> col:10 implicit struct UsesT
  | `-FieldDecl 0x8410 <col:18, col:28> col:28 a 'Tmpl<int>':'RE::Tmpl<int>'
  |-CXXRecordDecl 0x8488 <line:9:3, col:94> col:10 struct X definition
  | |-CXXRecordDecl 0x85c0 <col:3, col:10> col:10 implicit struct X
  | |-CXXMethodDecl 0x86c8 <col:14, col:30> col:27 XV 'void ()' virtual
  | |-CXXMethodDecl 0x87b0 <col:33, col:85> col:38 L 'void ()' implicit-inline
  | | `-CompoundStmt 0xc930 <col:42, col:85>
  | |   |-DeclStmt 0xc8c0 <col:44, col:74>
  | |   | `-VarDecl 0xa3e0 <col:44, col:73> col:49 used f '(lambda at RE/t.h:9:53)' cinit
  | |   |   `-LambdaExpr 0xb1b0 <col:53, col:73> '(lambda at RE/t.h:9:53)'
  | |   |     |-CXXRecordDecl 0xa450 <col:53> col:53 implicit class definition
  | |   |     | |-CXXMethodDecl 0xa5b8 <col:59, col:73> col:53 constexpr operator() 'int (int) const' inline
  | |   |     | | `-ParmVarDecl 0xa690 <col:56> col:59 'int'
  | |   |     | `-CXXDestructorDecl 0xc690 <col:53> col:53 implicit referenced constexpr ~(lambda at RE/t.h:9:53) 'void () noexcept' inline default trivial
  | |   |     `-CompoundStmt 0xa968 <col:61, col:73>
  | |-FieldDecl 0x8890 <col:87, col:91> col:91 x 'int'
  | `-CXXDestructorDecl 0xa290 <col:10> col:10 implicit constexpr ~X 'void ()' inline default trivial noexcept-unevaluated 0xa290
  `-CXXMethodDecl 0xc9e8 parent 0x8488 prev 0x86c8 <line:10:3, col:24> col:18 XV 'void ()' inline
    `-CompoundStmt 0xcae0 <col:23, col:24>
"""

# struct S { virtual void V(int) const noexcept; virtual void (*RetFp(int))(float);
#            virtual void Ov(int); virtual void Mid(); virtual void Ov(float);
#            void NV(); virtual void Late(); virtual void NV(int); };
# clang -fdump-vtable-layouts: V, RetFp, Ov(float), Ov(int), Mid, NV(int), Late
AST_OVERLOADS_X64 = r"""TranslationUnitDecl 0x6c90 <<invalid sloc>> <invalid sloc>
`-NamespaceDecl 0xda40 <RE/s.h:1:1, line:9:1> line:1:11 RE
  `-CXXRecordDecl 0xe0e8 <line:2:1, line:8:1> line:2:8 struct S definition
    |-CXXRecordDecl 0xe220 <col:1, col:8> col:8 implicit struct S
    |-CXXMethodDecl 0x6c90 <line:3:3, col:29> col:16 V 'void (int) const noexcept' virtual
    | `-ParmVarDecl 0xe470 <col:18> col:21 'int'
    |-CXXMethodDecl 0x7050 <line:4:3, col:35> col:18 RetFp 'void (*(int))(float)' virtual
    | `-ParmVarDecl 0x6e08 <col:24> col:27 'int'
    |-CXXMethodDecl 0x9cd8 <line:5:3, col:22> col:16 Ov 'void (int)' virtual
    | `-ParmVarDecl 0x9c20 <col:19> col:22 'int'
    |-CXXMethodDecl 0x9df8 <col:25, col:42> col:38 Mid 'void ()' virtual
    |-CXXMethodDecl 0x9f90 <col:45, col:66> col:58 Ov 'void (float)' virtual
    | `-ParmVarDecl 0x9ed8 <col:61> col:66 'float'
    |-CXXMethodDecl 0xa290 <line:6:3, col:11> col:8 NV 'void ()'
    |-CXXMethodDecl 0xa378 <col:14, col:32> col:27 referenced Late 'void ()' virtual
    `-CXXMethodDecl 0xa510 <col:35, col:54> col:48 NV 'void (int)' virtual
      `-ParmVarDecl 0xa458 <col:38> col:41 'int'
"""

LAYOUT_X64 = r"""
*** Dumping AST Record Layout
         0 | struct RE::P3
         0 |   float x
         4 |   float y
         8 |   float z
           | [sizeof=12, align=4,
           |  nvsize=12, nvalign=4]

*** Dumping AST Record Layout
         0 | struct RE::Holder::(unnamed at L/l.h:11:5)
         0 |   int q
         4 |   char c
           | [sizeof=8, align=4,
           |  nvsize=8, nvalign=4]

*** Dumping AST Record Layout
         0 | struct RE::Holder
         0 |   (Holder vftable pointer)
         8 |   struct RE::P3[4] pts
        56 |   struct RE::P3 *[2] ptrs
        72 |   int[2][3] m
        96 |   enum RE::Kind kind
       100 |   _Bool flag
       104 |   struct RE::P3 pos
       104 |     float x
       108 |     float y
       112 |     float z
       120 |   void * tail
       128 |   struct RE::Holder::(unnamed at L/l.h:11:5)[3] anonArr
       152 |   enum RE::Kind lastKind
       160 |   struct RE::Opaque * next
       168 |   char[] z
           | [sizeof=168, align=8,
           |  nvsize=168, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::Flat
         0 |   union RE::Flat::(anonymous at L/l.h:16:5)
         0 |     struct RE::Flat::(anonymous at L/l.h:16:13)
         0 |       unsigned int x
         4 |       unsigned int y
         0 |     unsigned long long both
         8 |   int last
           | [sizeof=16, align=8,
           |  nvsize=16, nvalign=8]
"""

# struct C : PolyA, PolyB { void Bar() override; virtual void G() override; virtual void Own(); };
# struct D : X, C { virtual void DOwn(); };
VTABLE_DUMP = r"""VFTable indices for 'RE::PolyA' (4 entries).
   0 | RE::PolyA::~PolyA() [scalar deleting]
   1 | void RE::PolyA::Foo(float)
   2 | void RE::PolyA::Foo(int)
   3 | void RE::PolyA::Bar()

VFTable for 'RE::PolyB' in 'RE::C' (3 entries).
   0 | RE::C RTTI
   1 | void RE::C::G()
   2 | void RE::PolyB::H()

VFTable indices for 'RE::C' (4 entries).
 -- accessible via vfptr at offset 0 --
   0 | RE::C::~C() [scalar deleting]
   3 | void RE::C::Bar()
   4 | void RE::C::Own()
 -- accessible via vfptr at offset 16 --
   0 | void RE::C::G()

VFTable for 'RE::PolyA' in 'RE::C' in 'RE::D' (6 entries).
   0 | RE::D RTTI
   1 | RE::D::~D() [scalar deleting]
       [this adjustment: -16 non-virtual]
   2 | void RE::PolyA::Foo(float)
   3 | void RE::PolyA::Foo(int)
   4 | void RE::C::Bar()
   5 | void RE::C::Own()

VFTable indices for 'RE::D' (2 entries).
 -- accessible via vfptr at offset 0 --
   1 | void RE::D::DOwn()
 -- accessible via vfptr at offset 16 --
   0 | RE::D::~D() [scalar deleting]

VFTable indices for 'RE::VDer' (2 entries).
 -- accessible via vfptr at offset 0 --
   0 | void RE::VDer::W()
 -- accessible via vbtable index 1, vfptr at offset 0 --
   0 | void RE::VDer::V()
"""


# namespace RE {
#   struct S1 { virtual void s(); virtual ~S1(); };
#   struct NA { virtual void a(); };
#   struct G : NA, S1 { virtual void s(float); virtual void w(); };
#   template <class E> struct Sink { virtual ~Sink(); virtual int Proc(const E& e) = 0; };
#   struct EvA {}; struct EvB {};
#   struct Multi : Sink<EvA>, Sink<EvB> {
#     virtual int Proc(const EvA& e); virtual int Proc(const EvB& e); virtual void Own(); };
#   template <class T> struct TM : NA, Sink<T> {
#     virtual int Proc(const T& e); virtual void s(float); virtual void Own2(); };
#   template <class T> struct TG : NA, S1 { virtual void s(float); virtual void w(); };
# }  // + template struct TM<EvA>; template struct TG<int>;
# clang -fdump-vtable-layouts, primary vfptr: G s=1 w=2; Multi ~=0 Proc(EvA)=1
# Own=2; TM<EvA> s=1 Own2=2; TG<int> s=1 w=2.
AST_SECONDARY_X64 = r"""TranslationUnitDecl 0x6c90 <<invalid sloc>> <invalid sloc>
`-NamespaceDecl 0xda40 <RE/t.h:1:1, line:10:1> line:1:11 RE
  |-CXXRecordDecl 0xdad0 <line:2:1, col:46> col:8 referenced struct S1 definition
  | |-CXXMethodDecl 0xdd48 <col:13, col:28> col:26 used s 'void ()' virtual
  | `-CXXDestructorDecl 0xdea0 <col:31, col:43> col:39 used ~S1 'void () noexcept' virtual
  |-CXXRecordDecl 0xe240 <line:3:1, col:31> col:8 referenced struct NA definition
  | `-CXXMethodDecl 0xe488 <col:13, col:28> col:26 used a 'void ()' virtual
  |-CXXRecordDecl 0x6f98 <line:4:1, col:62> col:8 struct G definition
  | |-public 'NA':'RE::NA'
  | |-public 'S1':'RE::S1'
  | |-CXXMethodDecl 0x7348 <col:21, col:41> col:34 s 'void (float)' virtual
  | | `-ParmVarDecl 0x7218 <col:36> col:41 'float'
  | |-CXXMethodDecl 0x7438 <col:44, col:59> col:57 w 'void ()' virtual
  | `-CXXDestructorDecl 0x8538 <col:8> col:8 implicit ~G 'void () noexcept' inline default
  |   `-Overrides: [ 0xdea0 S1::~S1 'void () noexcept' ]
  |-ClassTemplateDecl 0xabc8 <line:5:1, col:85> col:27 Sink
  | |-TemplateTypeParmDecl 0xaa40 <col:11, col:17> col:17 referenced class depth 0 index 0 E
  | `-CXXRecordDecl 0xab18 <col:20, col:85> col:27 struct Sink definition
  |   |-CXXDestructorDecl 0xaff0 <col:34, col:48> col:42 ~Sink<E> 'void ()' virtual not_selected
  |   `-CXXMethodDecl 0xb490 <col:51, col:82> col:63 Proc 'int (const E &)' virtual pure
  |     `-ParmVarDecl 0xb138 <col:68, col:77> col:77 e 'const E &'
  |-CXXRecordDecl 0xb560 <line:6:1, col:13> col:8 referenced struct EvA definition
  |-CXXRecordDecl 0xb768 <col:16, col:28> col:23 referenced struct EvB definition
  |-CXXRecordDecl 0xb968 <line:7:1, col:123> col:8 struct Multi definition
  | |-public 'Sink<EvA>':'RE::Sink<RE::EvA>'
  | |-public 'Sink<EvB>':'RE::Sink<RE::EvB>'
  | |-CXXMethodDecl 0xd340 <col:39, col:68> col:51 Proc 'int (const EvA &)' virtual
  | | |-Overrides: [ 0xc120 Sink::Proc 'int (const RE::EvA &)' ]
  | | `-ParmVarDecl 0xd210 <col:56, col:67> col:67 e 'const EvA &'
  | |-CXXMethodDecl 0xd590 <col:71, col:100> col:83 Proc 'int (const EvB &)' virtual
  | | |-Overrides: [ 0xcd20 Sink::Proc 'int (const RE::EvB &)' ]
  | | `-ParmVarDecl 0xd490 <col:88, col:99> col:99 e 'const EvB &'
  | |-CXXMethodDecl 0xd890 <col:103, col:120> col:116 Own 'void ()' virtual
  | `-CXXDestructorDecl 0xe558 <col:8> col:8 implicit ~Multi 'void () noexcept' inline default
  |   `-Overrides: [ 0xbe40 Sink::~Sink 'void () noexcept', 0xca48 Sink::~Sink 'void () noexcept' ]
  |-ClassTemplateDecl 0xec68 <line:8:1, col:120> col:27 TM
  | |-TemplateTypeParmDecl 0xeb08 <col:11, col:17> col:17 referenced class depth 0 index 0 T
  | `-CXXRecordDecl 0xebb8 <col:20, col:120> col:27 struct TM definition
  |   |-public 'NA':'RE::NA'
  |   |-public 'Sink<T>'
  |   |-CXXMethodDecl 0xf280 <col:46, col:73> col:58 Proc 'int (const T &)' virtual
  |   | `-ParmVarDecl 0xf148 <col:63, col:72> col:72 e 'const T &'
  |   |-CXXMethodDecl 0xf420 <col:76, col:96> col:89 s 'void (float)' virtual
  |   | `-ParmVarDecl 0xf368 <col:91> col:96 'float'
  |   `-CXXMethodDecl 0xf510 <col:99, col:117> col:112 Own2 'void ()' virtual
  `-ClassTemplateDecl 0xf748 <line:9:1, col:82> col:27 TG
    |-TemplateTypeParmDecl 0xf5f0 <col:11, col:17> col:17 class depth 0 index 0 T
    `-CXXRecordDecl 0xf698 <col:20, col:82> col:27 struct TG definition
      |-public 'NA':'RE::NA'
      |-public 'S1':'RE::S1'
      |-CXXMethodDecl 0x0248 <col:41, col:61> col:54 s 'void (float)' virtual
      | `-ParmVarDecl 0x0158 <col:56> col:61 'float'
      `-CXXMethodDecl 0x0338 <col:64, col:79> col:77 w 'void ()' virtual
"""

LAYOUT_SECONDARY_X64 = r"""
*** Dumping AST Record Layout
         0 | struct RE::NA
         0 |   (NA vftable pointer)
           | [sizeof=8, align=8,
           |  nvsize=8, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::S1
         0 |   (S1 vftable pointer)
           | [sizeof=8, align=8,
           |  nvsize=8, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::G
         0 |   struct RE::NA (primary base)
         0 |     (NA vftable pointer)
         8 |   struct RE::S1 (base)
         8 |     (S1 vftable pointer)
           | [sizeof=16, align=8,
           |  nvsize=16, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::Sink<struct RE::EvA>
         0 |   (Sink vftable pointer)
           | [sizeof=8, align=8,
           |  nvsize=8, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::Sink<struct RE::EvB>
         0 |   (Sink vftable pointer)
           | [sizeof=8, align=8,
           |  nvsize=8, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::Multi
         0 |   struct RE::Sink<struct RE::EvA> (primary base)
         0 |     (Sink vftable pointer)
         8 |   struct RE::Sink<struct RE::EvB> (base)
         8 |     (Sink vftable pointer)
           | [sizeof=16, align=8,
           |  nvsize=16, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::TM<EvA>
         0 |   struct RE::NA (primary base)
         0 |     (NA vftable pointer)
         8 |   struct RE::Sink<struct RE::EvA> (base)
         8 |     (Sink vftable pointer)
           | [sizeof=16, align=8,
           |  nvsize=16, nvalign=8]

*** Dumping AST Record Layout
         0 | struct RE::TG<int>
         0 |   struct RE::NA (primary base)
         0 |     (NA vftable pointer)
         8 |   struct RE::S1 (base)
         8 |     (S1 vftable pointer)
           | [sizeof=16, align=8,
           |  nvsize=16, nvalign=8]
"""


def _fields(record):
    return {f['name']: (f['offset'], f['size'], f['type']) for f in record['fields']}


# ---------------------------------------------------------------------------
# T1 -- method signatures
# ---------------------------------------------------------------------------

def test_t1_x86_thiscall_attribute_is_not_a_void_signature():
    sig = clang_types._parse_method_sig
    assert sig('void (int) __attribute__((thiscall))', None) == \
        ('void', [('p0', 'i32')])
    assert sig('RE::P3 () __attribute__((thiscall))', 'RE') == ('struct:RE::P3', [])
    # attribute precedes the cv / exception qualifiers on i686
    assert sig('bool (const char *) __attribute__((thiscall)) const noexcept', None) == \
        ('bool', [('p0', 'ptr:i8')])
    assert sig('In &(const In &) __attribute__((thiscall))', None) == \
        ('ptr:struct:In', [('p0', 'ptr:struct:In')])


def test_t1_function_pointer_params_template_commas_and_varargs():
    sig = clang_types._parse_method_sig
    assert sig('void (void (*)(int, float), int (S::*)(int) __attribute__((thiscall)), int)',
               None) == ('void', [('p0', 'ptr'), ('p1', 'ptr'), ('p2', 'i32')])
    assert sig('void (RE::BSTArray<int, RE::Alloc<1, 2>> &, int) const', 'RE') == (
        'void', [('p0', 'ptr:struct:RE::BSTArray<int, RE::Alloc<1, 2>>'), ('p1', 'i32')])
    # parentheses / commas inside template arguments belong to the type
    assert sig('int (std::function<void (int, int)>, std::pair<int, float>)', 'RE')[1][1] == \
        ('p1', 'struct:std::pair<int, float>')
    assert sig('std::function<void (int, int)> (float)', 'RE')[1] == [('p0', 'f32')]
    # ``...`` is dropped, never turned into a ``struct:RE::...`` parameter
    assert sig('int (const char *, ...)', 'RE') == ('i32', [('p0', 'ptr:i8')])
    assert sig('auto (int) const -> unsigned int', 'RE') == ('u32', [('p0', 'i32')])
    assert sig('auto (int) __attribute__((thiscall)) const -> bool', None) == \
        ('bool', [('p0', 'i32')])


def test_t1_unparseable_signature_is_none_not_void():
    sig = clang_types._parse_method_sig
    assert sig('void (*(int))(float)', 'RE') is None          # returns a fn pointer
    assert sig('void (*(int) __attribute__((thiscall)))(float)', None) is None
    assert sig('auto ()', 'RE') is None                       # undeduced
    assert sig('int', 'RE') is None
    assert sig('', 'RE') is None


def test_t1_callers_keep_the_slot_but_invent_no_signature():
    _enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_OVERLOADS_X64, 'RE', root_ns='RE', category_prefix='/T')
    s = classes['RE::S']
    assert s['vmethods']['RetFp'] is None          # still a vtable slot
    assert 'RetFp' not in s['methods']             # but no made-up ``void f()``
    assert s['vmethods']['V'] == ('void', [('p0', 'i32')])
    assert s['methods']['NV'] == ('void', [], False)
    # None signatures survive the downstream walkers
    structs = clang_types._merge_ast_and_layouts(classes, {}, 'RE', 'RE', '/T')
    clang_types._apply_aliases_to_structs(structs, {'RE::Foo': 'unsigned int'})
    clang_types._strip_anonymous_types(structs)
    assert clang_types._collect_descriptor_refs(structs) == set()


# ---------------------------------------------------------------------------
# T2 -- file path is printed only when it changes
# ---------------------------------------------------------------------------

def test_t2_every_declaration_of_an_in_scope_file_is_captured():
    enums, classes, aliases = clang_types._parse_ast_dump(
        AST_GLOBAL_X86, 'game', root_ns=None, category_prefix='/FNV')
    assert set(classes) == {'Base', 'Der'}
    assert set(enums) == {'E1', 'E2'}
    assert aliases == {'UInt32': 'unsigned int'}
    assert classes['Der']['bases'] == ['Base']
    assert classes['Base']['vmethods']['A'] == ('void', [('p0', 'struct:UInt32')])
    # a file outside the scope stays out
    enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_GLOBAL_X86, 'othergame', root_ns=None, category_prefix='/FNV')
    assert not enums and not classes


def test_t2_location_state_follows_clang_printing_rules():
    files = clang_types._ast_line_files
    assert files("NamespaceDecl 0x1 <inc\\RE/t.h:2:1, line:13:1> line:2:11 RE") == \
        ('inc\\RE/t.h', 'inc\\RE/t.h')
    assert files("CXXRecordDecl 0x1 <line:3:1, col:55> col:8 struct Der definition") == \
        (None, None)
    assert files("CXXRecordDecl 0x1 <<invalid sloc>> <invalid sloc> implicit class type_info") == \
        ('<invalid sloc>', None)
    assert files("FunctionDecl 0x1 <C:\\Program Files\\a b\\x.h:5:1, C:\\inc\\y.h:9:2> "
                 "C:\\inc\\z.h:7:3 f 'void ()'") == (
        'C:\\Program Files\\a b\\x.h', 'C:\\inc\\z.h')
    assert files("VarDecl 0x1 <<scratch space>:2:1, col:9> col:5 v 'int'") == \
        ('<scratch space>', '<scratch space>')
    # a name that merely looks like a location is not one
    assert files("CXXDestructorDecl 0x1 <col:53> col:53 implicit ~(lambda at RE/t.h:9:53) "
                 "'void ()'") == (None, None)
    assert files("TemplateArgument type 'int'") == (None, None)
    assert files("public 'BSTEventSink<RE::Foo>':'RE::BSTEventSink<RE::Foo>'") == (None, None)
    # include paths holding a quote or a comma keep their whole file name
    assert files("CXXRecordDecl 0x1 <C:/Users/O'Brien/inc/RE/a.h:5:1, line:9:1> "
                 "line:5:8 struct Foo definition") == (
        "C:/Users/O'Brien/inc/RE/a.h", "C:/Users/O'Brien/inc/RE/a.h")
    assert files("CXXRecordDecl 0x1 <C:/Mods, Tools/RE/a.h:5:1, C:/Mods,x/RE/b.h:9:1> "
                 "C:/O'B, y/RE/c.h:5:8 struct Foo definition") == (
        'C:/Mods, Tools/RE/a.h', "C:/O'B, y/RE/c.h")
    assert files("CXXRecordDecl 0x1 <col:3, line:9:1> line:5:8 struct Foo definition") == \
        (None, None)


# ---------------------------------------------------------------------------
# T3 -- array rewrite only for anonymous elements, in BYTES
# ---------------------------------------------------------------------------

def test_t3_named_arrays_survive_the_anonymous_type_strip():
    anon = 'RE::H::(unnamed at x.h:1:2)'
    structs = {
        'RE::H': {
            'name': 'H', 'full_name': 'RE::H', 'size': 96, 'bases': [],
            'fields': [
                {'name': 'pts', 'offset': 0, 'size': 48, 'type': 'arr:struct:RE::NiPoint3:4'},
                {'name': 'ptrs', 'offset': 48, 'size': 16, 'type': 'arr:ptr:2'},
                {'name': 'anon', 'offset': 64, 'size': 24, 'type': 'arr:struct:' + anon + ':3'},
                {'name': 'anonp', 'offset': 88, 'size': 8, 'type': 'arr:ptr:struct:' + anon + ':1'},
            ],
        },
        anon: {'name': '(unnamed)', 'full_name': anon, 'size': 8, 'bases': [], 'fields': []},
    }
    clang_types._strip_anonymous_types(structs)
    got = _fields(structs['RE::H'])
    assert got['pts'][2] == 'arr:struct:RE::NiPoint3:4'
    assert got['ptrs'][2] == 'arr:ptr:2'
    assert got['anon'][2] == 'bytes:24'            # byte size, not the count 3
    assert got['anonp'][2] == 'arr:ptr:1'
    assert anon not in structs


# ---------------------------------------------------------------------------
# T4 -- field sizes come from the type, not from the gap
# ---------------------------------------------------------------------------

def test_t4_fields_do_not_absorb_padding():
    layouts = clang_types._parse_layouts_with_bases(LAYOUT_X64, root_ns='RE', pointer_size=8)
    holder = _fields(layouts['RE::Holder'])
    assert holder['pts'][:2] == (8, 48)
    assert holder['ptrs'][:2] == (56, 16)
    assert holder['m'][:2] == (72, 24)
    assert holder['flag'][:2] == (100, 1)
    assert holder['pos'][:2] == (104, 12)          # 12-byte struct, 4 bytes padding follow
    assert holder['tail'][:2] == (120, 8)
    assert holder['anonArr'][:2] == (128, 24)
    assert holder['next'] == (160, 8, 'ptr:struct:RE::Opaque')
    assert holder['z'][:2] == (168, 0)             # flexible array: known zero
    # enum size is unknown to the layout pass: gap, until the AST enums arrive
    assert holder['kind'][:2] == (96, 4)
    assert holder['lastKind'][:2] == (152, 8)
    clang_types._refine_field_sizes(layouts, pointer_size=8, enum_sizes={'RE::Kind': 4})
    assert _fields(layouts['RE::Holder'])['lastKind'][:2] == (152, 4)


def test_t4_overlapping_union_member_is_not_dropped():
    layouts = clang_types._parse_layouts_with_bases(LAYOUT_X64, root_ns='RE', pointer_size=8)
    flat = _fields(layouts['RE::Flat'])
    assert flat['x'][:2] == (0, 4)
    assert flat['y'][:2] == (4, 4)                 # used to compute 0 -> dropped
    assert flat['both'][:2] == (0, 8)
    assert flat['last'][:2] == (8, 4)


def test_t4_typed_pointer_and_clamp_on_x86():
    fields = [
        {'name': 'form', 'offset': 0, 'size': 0, 'type': 'ptr:struct:TESForm'},
        {'name': 'big', 'offset': 8, 'size': 0, 'type': 'i64'},
        {'name': 'wrong', 'offset': 16, 'size': 0, 'type': 'struct:Collides'},
        {'name': 'end', 'offset': 20, 'size': 0, 'type': 'i32'},
    ]
    clang_types._backfill_sizes(fields, 24, pointer_size=4,
                                struct_sizes={'Collides': 64})
    assert [f['size'] for f in fields] == [4, 8, 4, 4]   # 64-byte type clamped to its slot


# ---------------------------------------------------------------------------
# T6 / T16 -- enums
# ---------------------------------------------------------------------------

def test_t6_plain_enum_without_underlying_type_is_int():
    enums, _classes, _aliases = clang_types._parse_ast_dump(
        AST_GLOBAL_X86, 'game', root_ns=None, category_prefix='/FNV')
    assert enums['E2']['size'] == 4
    assert enums['E2']['values'] == [('b', 0), ('c', 4)]
    parse = clang_types._parse_enum_decl
    assert parse("EnumDecl 0x1 <line:3:3, col:35> col:8 PlainEnum") == ('PlainEnum', None)
    assert parse("EnumDecl 0x1 <line:3:3, col:35> col:8 referenced PlainEnum") == ('PlainEnum', None)
    assert parse("EnumDecl 0x1 prev 0x2 <line:4:1> col:12 class E1 'int'") == ('E1', 'int')
    assert parse("EnumDecl 0x1 <col:1> col:6 U 'std::uint8_t':'unsigned char'") == \
        ('U', 'unsigned char')
    assert parse("EnumDecl 0x1 <line:5:1, col:18> col:1")[0] is None            # anonymous
    assert parse("EnumDecl 0x1 <line:5:1, col:18> col:1 'unsigned int'")[0] is None
    assert parse("EnumDecl 0x1 <col:51, col:56> col:56 TE instantiated_from 0x2") == ('TE', None)


def test_t16_enum_underlying_sizes():
    template = ("TranslationUnitDecl 0x1 <<invalid sloc>> <invalid sloc>\n"
                "`-NamespaceDecl 0x2 <RE/e.h:1:1, line:9:1> line:1:11 RE\n"
                "  `-EnumDecl 0x3 <line:2:3, col:40> col:14 class E '{}'\n"
                "    `-EnumConstantDecl 0x4 <col:30> col:30 kA 'RE::E'\n")
    for underlying, size in (('bool', 1), ('wchar_t', 2), ('char8_t', 1),
                             ('char16_t', 2), ('char32_t', 4), ('unsigned char', 1),
                             ('short', 2), ('unsigned long long', 8), ('__int64', 8),
                             ('int', 4)):
        enums, _c, _a = clang_types._parse_ast_dump(
            template.format(underlying), 'RE', root_ns='RE', category_prefix='/T')
        assert enums['RE::E']['size'] == size, underlying


# ---------------------------------------------------------------------------
# T10 / T9 -- AST-fallback vtable slots
# ---------------------------------------------------------------------------

def test_t10_derived_destructor_overrides_the_base_slot():
    _enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_GLOBAL_X86, 'game', root_ns=None, category_prefix='/FNV')
    structs = clang_types._merge_ast_and_layouts(classes, {}, 'game', None, '/FNV')
    clang_types._compute_vfuncs(structs, root_ns=None)
    assert structs['Base']['vfuncs'] == [('~Base', 0), ('A', 8)]
    # ~Der relabels slot 0; B is slot 2 (was 3 when ~Der counted as a new slot)
    assert structs['Der']['vfuncs'] == [('~Der', 0), ('B', 16)]


def test_t9_new_virtual_overloads_follow_msvc_group_order():
    _enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_OVERLOADS_X64, 'RE', root_ns='RE', category_prefix='/T')
    structs = clang_types._merge_ast_and_layouts(classes, {}, 'RE', 'RE', '/T')
    clang_types._compute_vfuncs(structs, root_ns='RE')
    # clang -fdump-vtable-layouts: V, RetFp, Ov(float), Ov(int), Mid, NV(int), Late
    assert structs['RE::S']['vfuncs'] == [
        ('V', 0), ('RetFp', 8), ('Ov', 16), ('Ov', 24), ('Mid', 32),
        ('NV', 40), ('Late', 48)]


# ---------------------------------------------------------------------------
# T11 / T12 -- class templates
# ---------------------------------------------------------------------------

def test_t11_template_enum_values_come_from_literals_or_the_enum_is_skipped():
    enums, _classes, _aliases = clang_types._parse_ast_dump(
        AST_TEMPLATE_X64, 'RE', root_ns='RE', category_prefix='/T')
    assert enums['RE::Tmpl::TE']['values'] == [
        ('kT0', 40), ('kT1', 41), ('kNeg', -2), ('kParen', 9)]
    # ``kD = sizeof(T)`` cannot be evaluated: no sequential guess (kD=0, kE=1)
    assert 'RE::Tmpl::Dep' not in enums
    # nothing from the ``Tmpl<int>`` instantiation leaks out as ``RE::TE`` / ``RE::Dep``
    assert set(enums) == {'RE::Tmpl::TE'}


def test_t12_specialization_members_never_land_on_the_namespace():
    _enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_TEMPLATE_X64, 'RE', root_ns='RE', category_prefix='/T')
    ns = classes['RE']
    assert ns['record_kind'] == 'namespace'
    assert ns['has_vtable'] is False
    assert ns['vmethods'] == {}
    assert set(ns['methods']) == {'FreeFn'}        # not TM / Plain / XV
    tmpl = classes['RE::Tmpl']
    assert tmpl['vmethods'] == {'TM': ('void', [('p0', 'struct:RE::T')])}
    assert '_overload_aliases' not in tmpl         # ``TM(int)`` is not an overload
    # the lambda's operator() belongs to the closure, not to RE::X
    assert set(classes['RE::X']['methods']) == {'XV', 'L'}
    structs = clang_types._merge_ast_and_layouts(classes, {}, 'RE', 'RE', '/T')
    clang_types._compute_vfuncs(structs, root_ns='RE')
    assert not [s['full_name'] for s in structs.values()
                if s['record_kind'] == 'namespace' and (s['has_vtable'] or s.get('vfuncs'))]


def test_t13_namespace_free_functions_carry_no_implicit_this():
    _enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_TEMPLATE_X64, 'RE', root_ns='RE', category_prefix='/T')
    # third element = "static" = the importer must not prepend ``RE* this``
    assert classes['RE']['methods']['FreeFn'] == ('void', [('p0', 'i32')], True)
    assert classes['RE::X']['methods']['XV'] == ('void', [], False)


# ---------------------------------------------------------------------------
# T15 / T18 -- type descriptors
# ---------------------------------------------------------------------------

# namespace RE { struct NiPoint3 { float x, y, z; }; using Buf = char[16];
#   using Mat = float[4][4]; using Pts = NiPoint3[3]; }
AST_ARRAY_ALIASES = r"""TranslationUnitDecl 0x6c90 <<invalid sloc>> <invalid sloc>
`-NamespaceDecl 0xda40 <RE/a.h:1:1, line:5:1> line:1:11 RE
  |-CXXRecordDecl 0xb5a0 <line:2:1, col:34> col:8 referenced struct NiPoint3 definition
  | |-FieldDecl 0xb7a8 <col:19, col:25> col:25 x 'float'
  | |-FieldDecl 0xb820 <col:19, col:28> col:28 y 'float'
  | `-FieldDecl 0xb898 <col:19, col:31> col:31 z 'float'
  |-TypeAliasDecl 0xb9d8 <line:3:1, col:20> col:7 referenced Buf 'char[16]'
  | `-ConstantArrayType 0xb970 'char[16]' 16
  |   `-BuiltinType 0x6d40 'char'
  |-TypeAliasDecl 0xbdd0 <line:4:1, col:23> col:7 referenced Mat 'float[4][4]'
  | `-ConstantArrayType 0xbd50 'float[4][4]' 4
  |   `-ConstantArrayType 0xbcf0 'float[4]' 4
  |     `-BuiltinType 0x6ea0 'float'
  `-TypeAliasDecl 0xc038 <line:5:1, col:23> col:7 referenced Pts 'NiPoint3[3]'
    `-ConstantArrayType 0xbfd0 'NiPoint3[3]' 3
"""


def test_t15_alias_to_primitive_loses_the_struct_prefix():
    resolve = clang_types._resolve_aliases_in_descriptor
    # Array targets exactly as the parser records them: the element must not
    # be root-qualified (``RE::char[16]`` made an opaque ``RE::char`` struct).
    _enums, _classes, parsed = clang_types._parse_ast_dump(
        AST_ARRAY_ALIASES, 'RE', root_ns='RE', category_prefix='/T')
    assert parsed == {'RE::Buf': 'char[16]', 'RE::Mat': 'float[4][4]',
                      'RE::Pts': 'RE::NiPoint3[3]'}
    assert resolve('struct:RE::Mat', parsed) == 'arr:arr:f32:4:4'
    assert resolve('struct:RE::Pts', parsed) == 'arr:struct:RE::NiPoint3:3'
    aliases = {'RE::FormID': 'unsigned int', 'RE::Chain': 'RE::FormID',
               'RE::Vec': 'RE::NiPoint3', 'RE::Buf': parsed['RE::Buf']}
    assert resolve('struct:RE::FormID', aliases) == 'u32'
    assert resolve('struct:RE::Chain', aliases) == 'u32'
    assert resolve('ptr:struct:RE::FormID', aliases) == 'ptr:u32'
    assert resolve('arr:struct:RE::FormID:4', aliases) == 'arr:u32:4'
    assert resolve('struct:RE::Vec', aliases) == 'struct:RE::NiPoint3'
    assert resolve('enum:RE::Vec', aliases) == 'enum:RE::NiPoint3'
    assert resolve('struct:RE::Buf', aliases) == 'arr:i8:16'
    assert resolve('struct:RE::Other', aliases) == 'struct:RE::Other'


def test_t12_instantiations_resolve_the_template_definitions_typedefs():
    # With instantiation subtrees ignored, ``RE::size_type`` is no longer a
    # (last-instantiation-wins) global alias; it resolves through the template
    # definition's own typedef, walking outwards like C++ name lookup.
    resolve = clang_types._resolve_aliases_in_descriptor
    aliases = {'RE::BSTArray::size_type': 'unsigned int',
               'RE::BSTArray::value_type': 'RE::T',
               'RE::Map::key_type': 'RE::Key'}
    scope = 'RE::BSTArray<RE::Actor *, RE::Alloc<1, 2>>'
    assert resolve('struct:RE::size_type', aliases, class_scope=scope) == 'u32'
    assert resolve('ptr:struct:RE::value_type', aliases, class_scope=scope) == 'ptr:struct:RE::T'
    assert resolve('struct:RE::key_type', aliases,
                   class_scope='RE::Map<int, float>::iterator_base<int>') == 'struct:RE::Key'
    # a name qualified with another class is never re-scoped
    assert resolve('struct:RE::Other<int>::size_type', aliases, class_scope=scope) ==         'struct:RE::Other<int>::size_type'
    assert resolve('struct:RE::size_type', aliases, class_scope='RE::Unrelated') ==         'struct:RE::size_type'


def test_t18_multi_dimensional_and_incomplete_arrays():
    conv = clang_types._record_type_to_pipeline
    assert conv('int[2][3]', 'RE') == 'arr:arr:i32:3:2'      # 2 x (3 x int)
    assert conv('float[4][4][2]', 'RE') == 'arr:arr:arr:f32:2:4:4'
    assert conv('char[]', 'RE') == 'arr:i8:0'
    assert conv('struct RE::P3[4]', 'RE') == 'arr:struct:RE::P3:4'
    assert conv('char *[3]', 'RE') == 'arr:ptr:i8:3'
    assert conv('int (*)[3]', 'RE') == 'ptr'
    assert conv('void (*[3])(int)', 'RE') == 'ptr'
    assert conv('RE::H::(unnamed at x.h:1:2)[3]', 'RE') == \
        'arr:struct:RE::H::(unnamed at x.h:1:2):3'
    assert clang_types._natural_size('arr:arr:i32:3:2') == 24
    assert clang_types._natural_size('arr:i8:0') == 0
    assert clang_types._natural_size('struct:RE::Unknown') is None


# ---------------------------------------------------------------------------
# T8 -- secondary vfptr groups in "VFTable indices"
# ---------------------------------------------------------------------------

def test_t8_secondary_vfptr_indices_stay_out_of_the_primary_table():
    primary, secondary = clang_types._parse_vtable_dump(VTABLE_DUMP, 'RE')
    assert primary['RE::PolyA'] == [(0, '~PolyA'), (1, 'Foo'), (2, 'Foo'), (3, 'Bar')]
    assert primary['RE::C'] == [(0, '~C'), (3, 'Bar'), (4, 'Own')]     # no (0, 'G')
    assert primary['RE::D'] == [(1, 'DOwn')]                            # no (0, '~D')
    assert primary['RE::VDer'] == [(0, 'W')]                            # vbase vfptr excluded
    assert secondary[('RE::D', 16)][0] == (0, '~D')

    structs = {'RE::C': {'full_name': 'RE::C', 'vmethods': {
        '~C': ('void', []), 'G': ('void', []), 'Own': ('void', [])}}}
    clang_types._apply_vtable_dump(structs, primary, 'RE')
    assert structs['RE::C']['vfuncs'] == [('~C', 0), ('Own', 32)]


def test_t8_overrides_of_a_secondary_base_add_no_primary_slots():
    # bhkCharRigidBodyController shape: every own virtual overrides the
    # SECONDARY base, so clang lists them only under ``vfptr at offset 16``.
    dump = '\n'.join([
        "VFTable indices for 'RE::Ctl' (2 entries).",
        " -- accessible via vfptr at offset 16 --",
        "   3 | void RE::Ctl::Callback()",
        "   4 | void RE::Ctl::Process()",
        ""])
    primary, _secondary = clang_types._parse_vtable_dump(dump, 'RE')
    assert primary == {'RE::Ctl': []}

    def st(name, bases, vmethods):
        return {'name': name.split('::')[-1], 'full_name': name, 'bases': bases,
                'has_vtable': True, 'vmethods': {m: ('void', []) for m in vmethods}}

    def build():
        return {
            'RE::Prim': st('RE::Prim', [], ['~Prim', 'A', 'B']),
            'RE::Listener': st('RE::Listener', [], ['~Listener', 'Callback', 'Process']),
            'RE::Ctl': st('RE::Ctl', ['RE::Prim', 'RE::Listener'], ['Callback', 'Process']),
            'RE::Leaf': st('RE::Leaf', ['RE::Ctl'], ['Extra']),
        }

    # AST fallback: the overrides are not new primary slots; Leaf's first new
    # slot follows Prim's three (it used to be pushed out to slot 5).
    structs = build()
    clang_types._compute_vfuncs(structs, root_ns='RE')
    assert not structs['RE::Ctl'].get('vfuncs')
    assert structs['RE::Leaf']['vfuncs'] == [('Extra', 24)]

    # Dump path: an empty primary group is authoritative, not "no data".
    structs = build()
    clang_types._apply_vtable_dump(structs, primary, 'RE')
    assert structs['RE::Ctl']['vfuncs'] == [] and structs['RE::Ctl']['_vfuncs_from_dump']
    clang_types._compute_vfuncs(structs, root_ns='RE')
    assert structs['RE::Ctl']['vfuncs'] == []


def test_secondary_base_name_match_overrides_only_with_the_same_signature():
    # AST fallback (instantiations, classes filtered from the dump, a failed
    # dump pass).  ``s(float)`` shares only its NAME with secondary base S1's
    # ``s()``: a new overload, so it keeps primary slot 1 and ``w`` stays at 2.
    # Multi's Proc overloads override its secondary Sink<EvB> (clang's
    # ``Overrides:``); TM's Proc overrides a dependent base clang could not
    # resolve, with the template's text (``const T &`` vs ``const E &``).
    _enums, classes, _aliases = clang_types._parse_ast_dump(
        AST_SECONDARY_X64, 'RE', root_ns='RE', category_prefix='/T')
    assert classes['RE::Multi']['_vm_overrides'] == ['Proc', 'Proc__overload_2']
    assert '_vm_overrides' not in classes['RE::G']
    layouts = clang_types._parse_layouts_with_bases(LAYOUT_SECONDARY_X64, root_ns='RE')
    structs = clang_types._merge_ast_and_layouts(classes, layouts, 'RE', 'RE', '/T')
    clang_types._compute_vfuncs(structs, root_ns='RE')
    assert structs['RE::G']['vfuncs'] == [('s', 8), ('w', 16)]
    assert structs['RE::TG<int>']['vfuncs'] == [('s', 8), ('w', 16)]
    assert structs['RE::TM<RE::EvA>']['vfuncs'] == [('s', 8), ('Own2', 16)]
    assert structs['RE::Multi']['vfuncs'] == [('Own', 16)]


# ---------------------------------------------------------------------------
# EnumSet / TEnumSet / stl::enumeration fields are their enum at storage width
# ---------------------------------------------------------------------------

# REX::EnumSet / REX::TEnumSet / SKSE::stl::enumeration<E, U = underlying(E)>:
#   struct Holder { virtual ~Holder();
#     REX::EnumSet<FormType, std::uint8_t> formType;           // enum : uint8
#     REX::TEnumSet<Actor::BOOL_FLAGS, std::uint32_t> boolFlags;
#     REX::EnumSet<Flags> deflt;                               // default U
#     SKSE::stl::enumeration<FormType, std::uint16_t> wide;
#     REX::TEnumSet<Flags, std::uint16_t> arr[2]; };
LAYOUT_ENUMSET_X64 = r"""
*** Dumping AST Record Layout
         0 | struct RE::Holder
         0 |   (Holder vftable pointer)
         8 |   class REX::EnumSet<enum RE::FormType, unsigned char> formType
         8 |     unsigned char _impl
        12 |   class REX::TEnumSet<enum RE::Actor::BOOL_FLAGS, unsigned int> boolFlags
        12 |     unsigned int _impl
        16 |   class REX::EnumSet<enum RE::Flags> deflt
        16 |     unsigned int _impl
        20 |   class SKSE::stl::enumeration<enum RE::FormType, unsigned short> wide
        20 |     class REX::EnumSet<enum RE::FormType, unsigned short> (base)
        20 |       unsigned short _impl
        22 |   REX::TEnumSet<Flags, std::uint16_t>[2] arr
           | [sizeof=32, align=8,
           |  nvsize=32, nvalign=8]
"""


def test_enumset_fields_are_typed_as_their_enum_at_storage_width():
    layouts = clang_types._parse_layouts_with_bases(LAYOUT_ENUMSET_X64, root_ns='RE')
    assert _fields(layouts['RE::Holder']) == {
        'formType': (8, 1, 'enum:RE::FormType:1'),
        'boolFlags': (12, 4, 'enum:RE::Actor::BOOL_FLAGS:4'),
        'deflt': (16, 4, 'enum:RE::Flags'),
        'wide': (20, 2, 'enum:RE::FormType:2'),
        'arr': (22, 4, 'arr:enum:RE::Flags:2:2')}
    conv = clang_types._record_type_to_pipeline
    # AST (sugared) spellings in method signatures
    assert conv('REX::EnumSet<FormType, std::uint8_t>', 'RE') == 'enum:RE::FormType:1'
    assert conv('REX::TEnumSet<Flags>', 'RE') == 'enum:RE::Flags'
    assert conv('const REX::EnumSet<RE::X, std::uint8_t> &', 'RE') == 'ptr:enum:RE::X:1'
    # an unknown storage width keeps the (right-sized) wrapper struct
    assert conv('REX::EnumSet<RE::X, std::size_t>', 'RE') == \
        'struct:REX::EnumSet<RE::X, std::size_t>'
    assert clang_types._natural_size('enum:RE::FormType:1') == 1
    # the width is not part of the name: no opaque ``RE::FormType:1`` record,
    # and an alias of the enum keeps the width
    assert clang_types._collect_descriptor_refs(
        {'H': {'fields': [{'type': 'enum:RE::FormType:1'}]}}) == {'RE::FormType'}
    assert clang_types._resolve_aliases_in_descriptor(
        'enum:RE::Alias:1', {'RE::Alias': 'RE::Real'}) == 'enum:RE::Real:1'
