# Try to find json-c
# Once done, this will define
#
# JSON-C_FOUND         - system has jsonc
# JSON-C_INCLUDE_DIRS  - the jsonc include directories
# JSON-C_LIBRARIES     - jsonc libraries directories

if(JSON-C_INCLUDE_DIRS AND JSON-C_LIBRARIES)
    set(JSONC_FIND_QUIETLY TRUE)
endif(JSON-C_INCLUDE_DIRS AND JSON-C_LIBRARIES)

find_path(JSON-C_INCLUDE_DIR json.h
    HINTS
    /usr/include/json-c/
    /usr/local/include/json-c/
    )

find_library(JSON-C_LIBRARY json-c
    HINTS
    /usr/lib/
    /usr/local/lib
    )

set(JSON-C_INCLUDE_DIRS ${JSON-C_INCLUDE_DIR})
set(JSON-C_LIBRARIES ${JSON-C_LIBRARY})
# handle the QUIETLY and REQUIRED arguments and set JSONC_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JSON-C DEFAULT_MSG JSON-C_INCLUDE_DIRS JSON-C_LIBRARIES)
mark_as_advanced(JSON-C_INCLUDE_DIRS JSON-C_LIBRARIES)
