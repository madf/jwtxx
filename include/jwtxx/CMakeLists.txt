set_source_files_properties ( version.h PROPERTIES GENERATED TRUE )

configure_file ( version.h.in version.h ESCAPE_QUOTES @ONLY )
