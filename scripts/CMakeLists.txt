function(add_kwin_script name)
    kpackage_install_package(${name} ${name} scripts kwin)

    # Copy the script to the build directory so one can run tests without prior
    # make install. FIXME: use add_custom_command.
    file(COPY ${name} DESTINATION ${CMAKE_BINARY_DIR}/bin/kwin/scripts/)
endfunction()

# videowall defines a KCModule service that has to be separately installed for the config dialog to be accessible
install(FILES videowall/metadata.desktop DESTINATION ${KDE_INSTALL_KSERVICES5DIR} RENAME kwin-script-videowall.desktop)
add_kwin_script(videowall)
add_kwin_script(synchronizeskipswitcher)
add_kwin_script(desktopchangeosd)
add_kwin_script(minimizeall)
