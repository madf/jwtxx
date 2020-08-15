find_path ( Jansson_INCLUDE_DIR NAMES jansson.h DOC "Path to Jansson header files." )
mark_as_advanced ( Jansson_INCLUDE_DIR )

find_library ( Jansson_LIB NAMES jansson DOC "Location of Jansson library." )
mark_as_advanced ( Jansson_LIB )

if ( Jansson_INCLUDE_DIR )
    file ( READ "${Jansson_INCLUDE_DIR}/jansson.h" ver )

    string ( REGEX MATCH "JANSSON_MAJOR_VERSION  ([0-9]*)" _ ${ver} )
    set ( ver_major ${CMAKE_MATCH_1} )

    string ( REGEX MATCH "JANSSON_MINOR_VERSION  ([0-9]*)" _ ${ver} )
    set ( ver_minor ${CMAKE_MATCH_1} )

    string ( REGEX MATCH "JANSSON_MICRO_VERSION  ([0-9]*)" _ ${ver} )
    set ( ver_micro ${CMAKE_MATCH_1} )

    set ( Jansson_VERSION "${ver_major}.${ver_minor}.${ver_micro}" )

    unset ( ver )
    unset ( ver_major )
    unset ( ver_minor )
    unset ( ver_micro )
endif ( Jansson_INCLUDE_DIR )

include ( FindPackageHandleStandardArgs )
find_package_handle_standard_args ( Jansson
                                    REQUIRED_VARS Jansson_LIB Jansson_INCLUDE_DIR
                                    VERSION_VAR Jansson_VERSION )

# Create the imported target
if ( Jansson_FOUND )
    set ( Jansson_INCLUDE_DIRS ${Jansson_INCLUDE_DIR} )
    set ( Jansson_LIBRARIES ${Jansson_LIB} )
    if ( NOT TARGET Jansson::Jansson )
        add_library ( Jansson::Jansson UNKNOWN IMPORTED )
        set_target_properties ( Jansson::Jansson PROPERTIES
                                IMPORTED_LOCATION "${Jansson_LIB}"
                                INTERFACE_INCLUDE_DIRECTORIES "${Jansson_INCLUDE_DIR}" )
    endif ( NOT TARGET Jansson::Jansson )
endif ( Jansson_FOUND )
