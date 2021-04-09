# Try to find json-c
# Once done, this will define
#
# JSON-C_FOUND        - system has jsonc
# JSON-C_INCLUDE_DIR  - the jsonc include directories
# JSON-C_LIBRARY     - jsonc libraries directories

if(JSON-C_INCLUDE_DIR AND JSON-C_LIBRARY)
    set(JSONC_FIND_QUIETLY TRUE)
endif()

find_path(JSON-C_INCLUDE_DIR NAMES json.h
    HINTS
    /usr/include/json-c/
    /usr/local/include/json-c/
    )

find_library(JSON-C_LIBRARY NAMES json-c
    HINTS
    /usr/lib/
    /usr/local/lib
    )

# handle the QUIETLY and REQUIRED arguments and set JSONC_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSON-C DEFAULT_MSG JSON-C_INCLUDE_DIR JSON-C_LIBRARY)
mark_as_advanced(JSON-C_INCLUDE_DIR JSON-C_LIBRARY)
