# - Try to find libbpf
# Once done this will define
#  LIBBPF_FOUND        - System has libbpf
#  LIBBPF_INCLUDE_DIRS - The libbpf include directories
#  LIBBPF_LIBRARIES    - The libraries needed to use libbpf

find_package(PkgConfig QUIET)
pkg_check_modules(PC_LIBBPF QUIET libbpf)
pkg_check_modules(PC_LIBELF QUIET libelf)
pkg_check_modules(PC_ZLIB QUIET zlib)

find_path(LIBBPF_INCLUDE_DIR
  NAMES bpf/bpf.h
  HINTS ${PC_LIBBPF_INCLUDE_DIRS}
  )
find_library(LIBBPF_LIBRARY
  NAMES bpf
  HINTS ${PC_LIBBPF_LIBRARY_DIRS}
  )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND
# to TRUE if all listed variables are TRUE and the requested version
# matches.
find_package_handle_standard_args(LibBpf REQUIRED_VARS
                                  LIBBPF_LIBRARY LIBBPF_INCLUDE_DIR
                                  VERSION_VAR LIBBPF_VERSION
                                  )

if(LIBBPF_FOUND)
  set(LIBBPF_LIBRARIES     ${LIBBPF_LIBRARY} ${PC_LIBELF_LIBRARIES} ${PC_ZLIB_LIBRARIES})
  set(LIBBPF_INCLUDE_DIRS  ${LIBBPF_INCLUDE_DIR} ${PC_LIBELF_INCLUDE_DIRS} ${PC_ZLIB_INCLUDE_DIRS})
endif()

mark_as_advanced(LIBBPF_INCLUDE_DIR LIBBPF_LIBRARY)
