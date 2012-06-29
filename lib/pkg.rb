require 'rubygems'
require 'ffi'


module Pkg
  extend ::FFI::Library
  ffi_lib "/root/pkgng/libpkg/libpkg.so.0"

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
        :repo, 0,
        :dbdir, 1,
        :cachedir, 2,
        :portsdir, 3,
        :repokey, 4,
        :multirepos, 5,
        :handle_rc_scripts, 6,
        :assume_always_yes, 7,
        :repos, 8,
        :plist_keywords_dir, 9,
        :syslog, 10,
        :shlibs, 11,
        :autodeps, 12,
        :abi, 13,
        :developer_mode, 14,
        :portaudit_site, 15
        )

  ConfigKey = enum(
        :repo, 0,
        :dbdir, 1,
        :cachedir, 2,
        :portsdir, 3,
        :repokey, 4,
        :multirepos, 5,
        :handle_rc_scripts, 6,
        :assume_always_yes, 7,
        :repos, 8,
        :plist_keywords_dir, 9,
        :syslog, 10,
        :shlibs, 11,
        :autodeps, 12,
        :abi, 13,
        :developer_mode, 14,
        :portaudit_site, 15
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
    layout :type, EventType,
           :event, EventU
  end

  class PkgLoad
    BASIC      = 0
    DEPS       = (1<<0)
    RDEPS      = (1<<1)
    FILES      = (1<<2)
    SCRIPTS    = (1<<3)
    OPTIONS    = (1<<4)
    MTREE      = (1<<5)
    DIRS       = (1<<6)
    CATEGORIES = (1<<7)
    LICENSES   = (1<<8)
    USERS      = (1<<9)
    GROUPS     = (1<<10)
    SHLIBS     = (1<<11)
  end

  class Db < ::FFI::Struct
    # sqlite3 *sqlite;
    # pkgdb_t type;
    layout :sqlite, :pointer,
           :type, DbType
  end

  attach_function :pkg_init, [:string], :int
  attach_function :pkg_shutdown, [:void], :void

  attach_function :pkgdb_open, [:pointer, DbType], :int

  # void pkgdb_close(struct pkgdb *db);
  attach_function :pkgdb_close, [:pointer], :void

  # Args: 
  #   struct pkgdb *db, const char *pattern, match_t match, unsigned int field, const char * reponame
  # Return:
  #   pointer to pkgdb_it
  attach_function :pkgdb_search, [:pointer, :string, Match, :int, :string], :pointer

  # struct pkgdb_it *pkgdb_query_installs(struct pkgdb *db, match_t type, int nbpkgs, char **pkgs, const char *reponame, bool force);
  attach_function :pkgdb_query_installs, [:pointer, Match, :int, :pointer, :string, :bool], :pointer

  #
  # int
  # pkgdb_it_next(struct pkgdb_it *it, struct pkg **pkg_p, int flags)
  attach_function :pkgdb_it_next, [:pointer, :pointer, :int], :int

  # void pkgdb_it_free(struct pkgdb_it *);
  attach_function :pkgdb_it_free, [:pointer], :void

  attach_function "pkg_get2", [:pointer, :varargs], :int


  # int pkg_config_string(pkg_config_key key, const char **value);
  attach_function :pkg_config_string, [ConfigKey, :pointer], :int

  # int pkg_config_bool(pkg_config_key key, bool *value);
  attach_function :pkg_config_bool, [ConfigKey, :pointer], :int

  # pkg_config_list(pkg_config_key key, struct pkg_config_kv **kv);
  attach_function :pkg_config_list, [ConfigKey, :pointer], :int

  # const char *pkg_config_kv_get(struct pkg_config_kv *kv, pkg_config_kv_t type);
  attach_function :pkg_config_kv_get, [:pointer, KeyvalueType], :string


  # int pkg_update(const char *name, const char *packagesite);
  attach_function :pkg_update, [:string, :string], :int


  # int pkg_jobs_new(struct pkg_jobs **jobs, pkg_jobs_t type, struct pkgdb *db);
  attach_function :pkg_jobs_new, [:pointer, JobsType, :pointer], :int

  # void pkg_jobs_free(struct pkg_jobs *jobs);
  attach_function :pkg_jobs_free, [:pointer], :void

  # int pkg_jobs_add(struct pkg_jobs *jobs, struct pkg *pkg);
  attach_function :pkg_jobs_add, [:pointer, :pointer], :int

  # int pkg_jobs_is_empty(struct pkg_jobs *jobs);
  attach_function :pkg_jobs_is_empty, [:pointer], :int

  # int pkg_jobs(struct pkg_jobs *jobs, struct pkg **pkg);
  attach_function :pkg_jobs, [:pointer, :pointer], :int

  # int pkg_jobs_apply(struct pkg_jobs *jobs, int force);
  attach_function :pkg_jobs_apply, [:pointer, :int], :int


  # typedef int(*pkg_event_cb)(void *, struct pkg_event *);
  callback :pkg_event_cb, [:pointer, :pointer], :int

  # void pkg_event_register(pkg_event_cb cb, void *data);
  attach_function :pkg_event_register, [:pkg_event_cb, :pointer], :void

  class EventHandler
    def self.install_begin(pkg)
      puts "Install begin"
      puts pkg
    end
    def self.install_finished(pkg)
      puts "Install finished"
      puts pkg
    end
    def self.deinstall_begin(pkg)
      puts "Deinstall begin"
      puts pkg
    end
    def self.deinstall_finished(pkg)
      puts "Deinstall finished"
      puts pkg
    end
    def self.upgrade_begin(pkg)
      puts "upgrade begin"
      puts pkg
    end
    def self.upgrade_finished(pkg)
      puts "upgrade finished"
      puts pkg
    end
    def self.fetching(url, total, done, elapsed)
      puts "fetching"
      puts url
      puts total
      puts done
      puts elapsed
    end
    def self.integritycheck_begin()
      puts "integritycheck begin"
    end
    def self.integritycheck_finished()
      puts "integritycheck finished"
    end
    def self.newpkgversion()
      puts "newpkgversion"
    end
    def self.error(msg)
      puts "error"
      puts msg
    end
    def self.errno(func, arg)
      puts "errno"
      puts func
      puts arg
    end
    def self.archive_comp_unsup()
      puts "archive comp unsup"
    end
    def self.already_installed(pkg)
      puts "already installed"
      puts pkg
    end
    def self.failed_cksum()
      puts "failed checksum"
    end
    def self.create_db_error()
      puts "create db error"
    end
    def self.required(pkg)
      puts "required"
      puts pkg
    end
    def self.noremotedb(repo)
      puts "noremotedb"
      puts repo
    end
    def self.nolocaldb()
      puts "nolocaldb"
    end

    def self.handle_event()
      Proc.new do |ptr, event_ptr|
        event = Event.new(event_ptr)

        case(event[:type])
          when :install_begin
            pkg = Pkg.new(event[:event][:install_begin][:pkg])
            EventHandler.install_begin(pkg)
          when :install_finished
            pkg = Pkg.new(event[:event][:install_finished][:pkg])
            EventHandler.install_finished(pkg)
          when :deinstall_begin
            pkg = Pkg.new(event[:event][:deinstall_begin][:pkg])
            EventHandler.deinstall_begin(pkg)
          when :deinstall_finished
            pkg = Pkg.new(event[:event][:deinstall_finished][:pkg])
            EventHandler.deinstall_finished(pkg)
          when :upgrade_begin
            pkg = Pkg.new(event[:event][:upgrade_begin][:pkg])
            EventHandler.upgrade_begin(pkg)
          when :upgrade_finished
            pkg = Pkg.new(event[:event][:upgrade_finished][:pkg])
            EventHandler.upgrade_finished(pkg)
          when :fetching
            url     = event[:event][:fetching][:url]
            total   = event[:event][:fetching][:total]
            done    = event[:event][:fetching][:done]
            elapsed = event[:event][:fetching][:elapsed]
            EventHandler.fetching(url, total, done, elapsed)
          when :integritycheck_begin
            EventHandler.integritycheck_begin()
          when :integritycheck_finished
            EventHandler.integritycheck_finished()
          when :newpkgversion
            EventHandler.newpkgversion()
          when :error
            msg = event[:event][:pkg_error][:msg]
            EventHandler.error(msg)
          when :errno
            func = event[:event][:errno][:func]
            arg  = event[:event][:errno][:arg]
            EventHandler.errno(func, arg)
          when :archive_comp_unsup
            EventHandler.archive_comp_unsup()
          when :already_installed
            pkg = Pkg.new(event[:event][:already_installed][:pkg])
            EventHandler.already_installed(pkg)
          when :failed_cksum
            EventHandler.failed_cksum()
          when :create_db_error
            EventHandler.create_db_error()
          when :required
            pkg   = Pkg.new(event[:event][:required][:pkg])
            force = event[:event][:required][:force]
            EventHandler.required(pkg)
          when :missing_dep
            # TODO: Missing pkg_dep_get binding
          when :noremotedb
            repo = event[:event][:remotedb][:repo]
            EventHandler.noremotedb(repo)
          when :nolocaldb
            EventHandler.nolocaldb()
          when :file_mismatch
            # TODO: Missing pkg_files binding
            #Pkg.new(event[:event][:file_mismatch][:pkg])
            #event[:event][:file_mismatch][:file]
            #event[:event][:file_mismatch][:newsum]
            #EventHandler.file_mismatch()
        end
      end
    end

    def self.install()
      ::Pkg.pkg_event_register(EventHandler.handle_event, ::FFI::Pointer::NULL)
    end
  end

  class Pkg
    def initialize(ptr)
      @pkg = ptr
    end

    def name
      Pkg.get_pkg(@pkg, [:name])[:name]
    end

    def self.init()
      if !defined?(@initialized)
        res = ::Pkg::pkg_init(nil)
        raise "pkg_init failed to initialize: #{res}" if res != 0

        @initialized = true

        # set destructor
        ObjectSpace.define_finalizer self, proc { Pkg.finalize() }
      end
    end

    def self.shutdown()
      puts "shutdown"
      ::Pkg::pkg_shutdown()
    end

    def self.read(ptr, field, output, &block)
      value_ptr = ptr.read_pointer()
      raise "NULL pointer for pkg value" if value_ptr.null?

      value = block.call value_ptr
      output[field] = value
    end

    def self.read_string(ptr, field, output)
      read(ptr, field, output) {|x| x.read_string()}
    end
    def self.read_uint64(ptr, field, output)
      read(ptr, field, output) {|x| x.read_double()}
    end
    def self.read_bool(ptr, field, output)
      read(ptr, field, output) {|x| (value_ptr.read_bytes(1) == "\001")}
    end
    def self.read_license(ptr, field, output)
      read(ptr, field, output) {|x| License.from_native(value_ptr.read_byte(1))}
    end

    def self.get_pkg(pkg, fields)
      args = []
      args << pkg

      read_values = []

      output = {}

      fields.each do |field|
        if not Attributes[field].nil?
          args << Attributes
          args << Attributes[field]
          args << :pointer
          if Attributes[field] < ::Pkg::PKG_NUM_FIELDS
            ptr = ::FFI::MemoryPointer.new(:pointer)
            args << ptr
            read_values << lambda {Pkg.read_string(ptr, field, output)}
          else
            case (field)
              when :new_flatsize, :flatsize, :new_pkgsize, :time, :rowid
                #int64_t
                ptr = ::FFI::MemoryPointer.new(:int64)
                args << ptr
                read_values << lambda {Pkg.read_uint64(ptr, field, output)}
              when :automatic
                #bool_t
                ptr = ::FFI::MemoryPointer.new(:bool)
                args << ptr
                read_values << lambda {Pkg.read_bool(ptr, field, output)}
              when :license_logic
                #lic_t
                ptr = ::FFI::MemoryPointer.new(:char)
                args << ptr
                read_values << lambda {Pkg.read_license(ptr, field, output)}
              else
                #otherwise ignore
                args.pop()
                args.pop()
                args.pop()
            end
          end
        end
      end

      ::Pkg.pkg_get2(*args)

      read_values.each do |f|
        f.call
      end

      output
    end
  end

  class Jobs
    def initialize(db, type = :install)
      jobs_ptr = ::FFI::MemoryPointer.new(:pointer)

      res = ::Pkg.pkg_jobs_new(jobs_ptr, type, db)
      raise "Couldn't initialize jobs" if res != Epkg[:ok]

      @jobs = jobs_ptr.read_pointer()

      ObjectSpace.define_finalizer @jobs, proc { Jobs.finalize(@jobs) }
    end

    def self.finalize(ptr)
      ::Pkg.pkg_jobs_free(ptr)
    end

    def add(pkg)
      res = ::Pkg.pkg_jobs_add(@jobs, pkg)
      raise "Couldn't add job" if res != Epkg[:ok]
    end

    def apply(force = false)
      flags = force ? 1 : 0
      res = ::Pkg.pkg_jobs_apply(@jobs, flags)
      raise "Couldn't apply jobs: #{Epkg[res]}" if res != Epkg[:ok]
    end
  end

  class Repo
    def initialize(name, packagesite)
      @name = name
      @packagesite = packagesite
    end

    def update
      res = ::Pkg.pkg_update(@name, @packagesite)

      raise "Update failed with return code : #{res}" if res != Epkg[:ok] and res != Epkg[:uptodate]
    end

    def inspect
      "#<Pkg::Repo #{@name} #{@packagesite}>"
    end

    def self.list
      Pkg.init()

      repos = []

      # Check if we need multirepos or not
      ptr = ::FFI::MemoryPointer.new(:bool)
      res = ::Pkg.pkg_config_bool(PkgConfig[:multirepos], ptr)
      raise "couldn't read config" if res != Epkg[:ok]

      multirepos = (ptr.read_bytes(1) == "\001")

      if multirepos
        repokv_ptr_ptr = ::FFI::MemoryPointer.new(:pointer)

        while (::Pkg.pkg_config_list(ConfigKey[:repos], repokv_ptr_ptr) == Epkg[:ok]) do
          repokv_ptr = repokv_ptr_ptr.read_pointer()

          name = ::Pkg.pkg_config_kv_get(repokv_ptr, KeyvalueType[:key])
          packagesite = ::Pkg.pkg_config_kv_get(repokv_ptr, KeyvalueType[:value])

          repos << Repo.new(name, packagesite)
        end
      else
        ptr = ::FFI::MemoryPointer.new(:pointer)
        res = ::Pkg.pkg_config_string(ConfigKey[:repo], ptr)
        raise "couldn't read config" if res != Epkg[:ok]

        packagesite_ptr = ptr.read_pointer()
        raise "PACKAGESITE is not defined." if packagesite_ptr.null?

        repos << Repo.new("repo", packagesite_ptr)
      end
      repos
    end
  end

  class Search
    def initialize(db_type = :default)
      ::Pkg::Pkg.init()

      db_ptr_ptr = FFI::MemoryPointer.new(:pointer)
      res = ::Pkg.pkgdb_open(db_ptr_ptr, db_type)

      raise "pkgdb_open failed: #{res}" if res != Epkg[:ok]

      @db_pointer = db_ptr_ptr.read_pointer()
      raise "NULL pointer for db pointer" if @db_pointer.null?

      @jobs = {}

      # set destructor
      ObjectSpace.define_finalizer @db_pointer, proc { Search.finalize(@db_pointer) }
    end

    def self.finalize(ptr)
      ::Pkg.pkgdb_close(ptr)
    end

    SEARCH_DEFAULT = {
      :match => Match[:regex],
      :field => Field[:name],
      :reponame => "default",
      :return => [:name],
      :force => false
    }

    def search(pattern, opts={})
      options = SEARCH_DEFAULT.merge(opts)

      ary = []

      begin
        it_ptr = ::Pkg.pkgdb_search(@db_pointer, pattern, options[:match], options[:field], options[:reponame])
        # no results
        raise "Search returned NULL" if it_ptr.null?

        pkg_ptr = ::FFI::MemoryPointer.new(:pointer)

        while((res = ::Pkg.pkgdb_it_next(it_ptr, pkg_ptr, PkgLoad::BASIC)) == Epkg[:ok]) do
          pkg = pkg_ptr.read_pointer()
          ary << Pkg.get_pkg(pkg, options[:return])
        end
      ensure
        # Cleanup
        ::Pkg.pkgdb_it_free(it_ptr)
      end

      ary
    end

    def search_install(packages, opts={})
      Pkg.init()

      options = SEARCH_DEFAULT.merge(opts)
      job = Jobs.new(@db_pointer, :fetch)

      if packages.class == String
        packages = [packages]
      end

      begin
        package_ary = []
        packages.each do |pkg|
          package_ary << ::FFI::MemoryPointer.from_string(pkg)
        end
        package_ary << nil

        package_ptr = FFI::MemoryPointer.new(:pointer, package_ary.length)
        package_ary.each_with_index do |p, i|
          package_ptr[i].put_pointer(0, p)
        end

        it_ptr = ::Pkg.pkgdb_query_installs(@db_pointer, options[:match], packages.size(), package_ptr, options[:reponame], options[:force])
        # no results
        raise "Search returned NULL" if it_ptr.null?

        pkg_ptr = ::FFI::MemoryPointer.new(:pointer)

        while((res = ::Pkg.pkgdb_it_next(it_ptr, pkg_ptr, PkgLoad::BASIC || PkgLoad::DEPS)) == Epkg[:ok]) do
          pkg = pkg_ptr.read_pointer()

          job.add(pkg)
        end
      ensure
        # Cleanup
        ::Pkg.pkgdb_it_free(it_ptr)
      end

      job
    end

  end
end
