require 'pkg/enum'


module Pkg
  module Struct

# struct {
#         const char *func;
#         const char *arg;
# } e_errno;
    class EventErrno < ::FFI::Struct
      layout :func, :string,
             :arg, :string
    end

# struct {
#         char *msg;
# } e_pkg_error;
    class EventPkgError < ::FFI::Struct
      layout :msg, :string
    end

# struct {
#         const char *url;
#         off_t total;
#         off_t done;
#         time_t elapsed;
# } e_fetching;
    class EventFetching < ::FFI::Struct
      layout :url, :string,
             :total, :off_t,
             :done, :off_t,
             :elapsed, :time_t
    end

# struct {
#         struct pkg *pkg;
# } e_already_installed;
    class EventAlreadyInstalled < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
# } e_install_begin;
    class EventInstallBegin < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
# } e_install_finished;
    class EventInstallFinished < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
# } e_deinstall_begin;
    class EventDeinstallBegin < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
# } e_deinstall_finished;
    class EventDeinstallFinished < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
# } e_upgrade_begin;
    class EventUpgradeBegin < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
# } e_upgrade_finished;
    class EventUpgradeFinished < ::FFI::Struct
      layout :pkg, :pointer
    end

# struct {
#         struct pkg *pkg;
#         struct pkg_dep *dep;
# } e_missing_dep;
    class EventMissingDep < ::FFI::Struct
      layout :pkg, :pointer,
             :pkg_dep, :pointer
    end

# struct {
#         struct pkg *pkg;
#         int force;
# } e_required;
    class EventRequired < ::FFI::Struct
      layout :pkg, :pointer,
             :force, :int
    end

# struct {
#         const char *repo;
# } e_remotedb;
    class EventRemotedb < ::FFI::Struct
      layout :repo, :string
    end

# struct {
#         struct pkg *pkg;
#         struct pkg_file *file;
#         const char *newsum;
# } e_file_mismatch;
    class EventFileMismatch < ::FFI::Struct
      layout :pkg, :pointer,
             :file, :pointer,
             :newsum, :string
    end

    class EventU < ::FFI::Union
      layout :errno,              EventErrno,
             :pkg_error,          EventPkgError,
             :fetching,           EventFetching,
             :already_installed,  EventAlreadyInstalled,
             :install_begin,      EventInstallBegin,
             :install_finished,   EventInstallFinished,
             :deinstall_begin,    EventDeinstallBegin,
             :deinstall_finished, EventDeinstallFinished,
             :upgrade_begin,      EventUpgradeBegin,
             :upgrade_finished,   EventUpgradeFinished,
             :missing_dep,        EventMissingDep,
             :required,           EventRequired,
             :remotedb,           EventRemotedb,
             :file_mismatch,      EventFileMismatch
    end

    class Event < ::FFI::Struct
      layout :type, Enum::EventType,
             :event, EventU
    end

    class Db < ::FFI::Struct
      # sqlite3 *sqlite;
      # pkgdb_t type;
      layout :sqlite, :pointer,
             :type, Enum::DbType
    end

  end
end


