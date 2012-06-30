require 'ffi'

module Pkg
  module Enum

    private
    # Helper to construct enum
    def self.enum(*args)
      ::FFI::Enum.new(args)
    end

    DbType = enum(:default,
                  :remote)

    Epkg = enum(
          :ok,
          :end,
          :warn,
          :fatal,
          :required,
          :installed,
          :dependency,
          :enodb,
          :uptodate,
          :unknown
          )

    Field = enum(
          :none,
          :origin,
          :name,
          :namever,
          :comment,
          :desc
          )

    Match = enum(
          :all,
          :exact,
          :glob,
          :regex,
          :eregex,
          :condition)

    Attributes = enum(
          :origin, 1,
          :name,
          :version,
          :comment,
          :desc,
          :mtree,
          :message,
          :arch,
          :maintainer,
          :www,
          :prefix,
          :infos,
          :repopath,
          :cksum,
          :newversion,
          :reponame,
          :repourl,
          :flatsize,
          :new_flatsize,
          :new_pkgsize,
          :license_logic,
          :automatic,
          :rowid,
          :time)



    PKG_NUM_FIELDS=64

    License = enum(
          :or,     '|',
          :and,    '&',
          :single, 1
          )

    PkgConfig = enum(
          :repo,               0,
          :dbdir,              1,
          :cachedir,           2,
          :portsdir,           3,
          :repokey,            4,
          :multirepos,         5,
          :handle_rc_scripts,  6,
          :assume_always_yes,  7,
          :repos,              8,
          :plist_keywords_dir, 9,
          :syslog,             10,
          :shlibs,             11,
          :autodeps,           12,
          :abi,                13,
          :developer_mode,     14,
          :portaudit_site,     15
          )

    ConfigKey = enum(
          :repo,               0,
          :dbdir,              1,
          :cachedir,           2,
          :portsdir,           3,
          :repokey,            4,
          :multirepos,         5,
          :handle_rc_scripts,  6,
          :assume_always_yes,  7,
          :repos,              8,
          :plist_keywords_dir, 9,
          :syslog,             10,
          :shlibs,             11,
          :autodeps,           12,
          :abi,                13,
          :developer_mode,     14,
          :portaudit_site,     15
          )

    KeyvalueType = enum(
          :key,
          :value
          )

    JobsType = enum(
          :install,
          :deinstall,
          :fetch
          )

    EventType = enum(
          :install_begin, 0,
          :install_finished,
          :deinstall_begin,
          :deinstall_finished,
          :upgrade_begin,
          :upgrade_finished,
          :fetching,
          :integritycheck_begin,
          :integritycheck_finished,
          :newpkgversion,

          :error,
          :errno,
          :archive_comp_unsup, 65536,
          :already_installed,
          :failed_cksum,
          :create_db_error,
          :required,
          :missing_dep,
          :noremotedb,
          :nolocaldb,
          :file_mismatch
          )


  end
end