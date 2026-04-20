include_guard(GLOBAL)

function(spine_install_runtime_assets)
  set(SPINE_BIN_PATH "${CMAKE_INSTALL_FULL_SBINDIR}/spine")
  set(SPINE_CONF_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/spine.conf")
  string(REPLACE "." "\\." SPINE_BIN_PATH_SELINUX "${SPINE_BIN_PATH}")
  string(REPLACE "." "\\." SPINE_CONF_PATH_SELINUX "${SPINE_CONF_PATH}")
  string(REGEX REPLACE "^/" "" SPINE_APPARMOR_PROFILE_BASENAME "${SPINE_BIN_PATH}")
  string(REPLACE "/" "." SPINE_APPARMOR_PROFILE_BASENAME "${SPINE_APPARMOR_PROFILE_BASENAME}")

  configure_file(
    ${CMAKE_SOURCE_DIR}/etc/systemd/spine.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/spine.service
    @ONLY)
  configure_file(
    ${CMAKE_SOURCE_DIR}/etc/systemd/spine-batch.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/spine-batch.service
    @ONLY)
  configure_file(
    ${CMAKE_SOURCE_DIR}/etc/systemd/spine-dynamic.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/spine-dynamic.service
    @ONLY)
  configure_file(
    ${CMAKE_SOURCE_DIR}/etc/selinux/spine.fc.in
    ${CMAKE_CURRENT_BINARY_DIR}/spine.fc
    @ONLY)
  configure_file(
    ${CMAKE_SOURCE_DIR}/etc/apparmor.d/spine.apparmor.in
    ${CMAKE_CURRENT_BINARY_DIR}/${SPINE_APPARMOR_PROFILE_BASENAME}
    @ONLY)

  # Install unit + timer into the distro-provided systemd unit directory.
  # Falls back to /lib/systemd/system when pkg-config cannot resolve the
  # variable (older systemd on some long-term-support distros).
  if(WITH_SYSTEMD AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(NOT SPINE_SYSTEMD_UNIT_DIR)
      set(SPINE_SYSTEMD_UNIT_DIR "/lib/systemd/system")
    endif()
    install(
      FILES ${CMAKE_CURRENT_BINARY_DIR}/spine.service
            ${CMAKE_CURRENT_BINARY_DIR}/spine-batch.service
            ${CMAKE_CURRENT_BINARY_DIR}/spine-dynamic.service
            ${CMAKE_SOURCE_DIR}/etc/systemd/spine.timer
      DESTINATION ${SPINE_SYSTEMD_UNIT_DIR}
      COMPONENT systemd)
  endif()

  # Packaging helpers for distro-managed MAC enforcement. These are shipped
  # under ${datadir}/spine so distro packagers can symlink them into
  # /etc/apparmor.d and /usr/share/selinux/packages respectively. Installing
  # them directly into /etc would collide with dpkg/rpm file ownership.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(
      FILES ${CMAKE_CURRENT_BINARY_DIR}/${SPINE_APPARMOR_PROFILE_BASENAME}
      DESTINATION ${CMAKE_INSTALL_DATADIR}/spine/apparmor
      COMPONENT apparmor
      OPTIONAL)
    install(
      FILES ${CMAKE_SOURCE_DIR}/etc/selinux/spine.te
            ${CMAKE_CURRENT_BINARY_DIR}/spine.fc
            ${CMAKE_SOURCE_DIR}/etc/selinux/spine.if
      DESTINATION ${CMAKE_INSTALL_DATADIR}/spine/selinux
      COMPONENT selinux
      OPTIONAL)
  endif()
endfunction()

function(spine_configure_cpack)
  # CPack: source tarballs plus distro-native packages on Linux. DEB/RPM rely
  # on cpack driving dpkg-deb / rpmbuild at build-tree time; the TGZ fallback
  # covers platforms where neither tool is available (macOS, BSDs, Windows).
  set(CPACK_PACKAGE_NAME "spine" PARENT_SCOPE)
  set(CPACK_PACKAGE_VENDOR "The Cacti Group" PARENT_SCOPE)
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "High-speed poller for Cacti" PARENT_SCOPE)
  set(CPACK_PACKAGE_VERSION "${spine_VERSION}" PARENT_SCOPE)
  set(CPACK_PACKAGE_CONTACT "cacti-users@cacti.net" PARENT_SCOPE)
  set(CPACK_PACKAGE_HOMEPAGE_URL "https://www.cacti.net/spine.php" PARENT_SCOPE)
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE" PARENT_SCOPE)

  set(CPACK_SOURCE_GENERATOR "TGZ" PARENT_SCOPE)
  set(CPACK_SOURCE_IGNORE_FILES
      "/build.*/"
      "/\\\\.git/"
      "/\\\\.github/"
      "/build-reports/"
      "/\\\\.omc/"
      "/\\\\.claude/"
      "/\\\\.worktrees/"
      "\\\\.php-cs-fixer.cache"
      "\\\\.DS_Store"
      PARENT_SCOPE)
  set(CPACK_SOURCE_PACKAGE_FILE_NAME "spine-${spine_VERSION}" PARENT_SCOPE)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_spine_cpack_generator "TGZ;DEB;RPM")
    set(CPACK_GENERATOR "${_spine_cpack_generator}" PARENT_SCOPE)
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "The Cacti Group <cacti-users@cacti.net>" PARENT_SCOPE)
    set(CPACK_DEBIAN_PACKAGE_SECTION "net" PARENT_SCOPE)
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON PARENT_SCOPE)
    set(CPACK_RPM_PACKAGE_LICENSE "GPL-2.0-or-later" PARENT_SCOPE)
    set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet" PARENT_SCOPE)
    set(CPACK_RPM_PACKAGE_URL "https://www.cacti.net/spine.php" PARENT_SCOPE)
  endif()
endfunction()
