require 'rubygems'
require 'ffi'



module Pkg
  extend ::FFI::Library
  ffi_lib "/root/pkgng/libpkg/libpkg.so.0"

  require 'pkg/enum'
  require 'pkg/struct'

  attach_function :pkg_init, [:string], :int
  attach_function :pkg_shutdown, [:void], :void

  attach_function :pkgdb_open, [:pointer, Enum::DbType], :int

  # void pkgdb_close(struct pkgdb *db);
  attach_function :pkgdb_close, [:pointer], :void

  # Args: 
  #   struct pkgdb *db, const char *pattern, match_t match, unsigned int field, const char * reponame
  # Return:
  #   pointer to pkgdb_it
  attach_function :pkgdb_search, [:pointer, :string, Enum::Match, :int, :string], :pointer

  # struct pkgdb_it *pkgdb_query_installs(struct pkgdb *db, match_t type, int nbpkgs, char **pkgs, const char *reponame, bool force, bool recursive);
  attach_function :pkgdb_query_installs, [:pointer, Enum::Match, :int, :pointer, :string, :bool, :bool], :pointer

  #
  # int
  # pkgdb_it_next(struct pkgdb_it *it, struct pkg **pkg_p, int flags)
  attach_function :pkgdb_it_next, [:pointer, :pointer, :int], :int

  # void pkgdb_it_free(struct pkgdb_it *);
  attach_function :pkgdb_it_free, [:pointer], :void

  attach_function "pkg_get2", [:pointer, :varargs], :int

  # const char * pkg_dep_get(struct pkg_dep const * const d, const pkg_dep_attr attr)
  attach_function :pkg_dep_get, [:pointer, Enum::DepAttr], :string

  # int pkg_config_string(pkg_config_key key, const char **value);
  attach_function :pkg_config_string, [Enum::ConfigKey, :pointer], :int

  # int pkg_config_bool(pkg_config_key key, bool *value);
  attach_function :pkg_config_bool, [Enum::ConfigKey, :pointer], :int

  # pkg_config_list(pkg_config_key key, struct pkg_config_kv **kv);
  attach_function :pkg_config_list, [Enum::ConfigKey, :pointer], :int

  # const char *pkg_config_kv_get(struct pkg_config_kv *kv, pkg_config_kv_t type);
  attach_function :pkg_config_kv_get, [:pointer, Enum::KeyvalueType], :string


  # int pkg_update(const char *name, const char *packagesite);
  attach_function :pkg_update, [:string, :string], :int


  # int pkg_jobs_new(struct pkg_jobs **jobs, pkg_jobs_t type, struct pkgdb *db);
  attach_function :pkg_jobs_new, [:pointer, Enum::JobsType, :pointer], :int

  # void pkg_jobs_free(struct pkg_jobs *jobs);
  attach_function :pkg_jobs_free, [:pointer], :void

  # int pkg_jobs_add(struct pkg_jobs *jobs, struct pkg *pkg);
  attach_function :pkg_jobs_add, [:pointer, :pointer], :int

  # int pkg_jobs(struct pkg_jobs *jobs, struct pkg **pkg);
  attach_function :pkg_jobs, [:pointer, :pointer], :int

  # int pkg_jobs_apply(struct pkg_jobs *jobs, int force);
  attach_function :pkg_jobs_apply, [:pointer, :int], :int


  # typedef int(*pkg_event_cb)(void *, struct pkg_event *);
  callback :pkg_event_cb, [:pointer, :pointer], :int

  # void pkg_event_register(pkg_event_cb cb, void *data);
  attach_function :pkg_event_register, [:pkg_event_cb, :pointer], :void

  module EventHandler
    require "logger"

    class Handler
      def initialize()
        @logger = Logger.new(STDOUT)
      end

      def install_begin(pkg)
        @logger.info("Install begin: #{pkg}")
      end
      def install_finished(pkg)
        @logger.info("Install finished: #{pkg}")
      end
      def deinstall_begin(pkg)
        @logger.info("Deinstall begin: #{pkg}")
      end
      def deinstall_finished(pkg)
        @logger.info("Deinstall finished: #{pkg}")
      end
      def upgrade_begin(pkg)
        @logger.info("Upgrade begin: #{pkg}")
      end
      def upgrade_finished(pkg)
        @logger.info("Upgrade finished: #{pkg}")
      end
      def fetching(url, total, done, elapsed)
        @logger.info("Fetching from #{url}(#{total}), #{done} in #{elapsed}")
      end
      def integritycheck_begin()
        @logger.info("Integritycheck begin")
      end
      def integritycheck_finished()
        @logger.info("Integritycheck finished")
      end
      def newpkgversion()
        # TODO WTF?
        @logger.info("New pkg version")
      end
      def error(msg)
        @logger.error(msg)
      end
      def errno(func, arg)
        @logger.error("#{func}(#{arg})")
      end
      def archive_comp_unsup()
        # TODO WTF?
        @logger.info("Archive comp unsup")
      end
      def already_installed(pkg)
        @logger.info("Package #{pkg} already installed")
      end
      def failed_cksum()
        @logger.error("Failed checksum")
      end
      def create_db_error()
        @logger.error("Create db error")
      end
      def required(pkg)
        @logger.info("Required")
      end
      def noremotedb(repo)
        @logger.warn("repo #{repo} doesn't exists")
      end
      def nolocaldb()
        @logger.warn("Local db doesn't exists")
      end
      def missing_dep(name, origin, version)
        @logger.error("Missing dependency on #{name}(#{version}) for #{origin}")
      end
    end


    @handler = nil

    # Get the current handler or initialize a new one if none available
    def self.handler
      @handler || init
    end

    # Register a new handler
    def self.handler=(h)
      @handler = h
    end

    # This method is called by pkgng when an event is emitted
    # It will decode the event and call the handler with content
    HandleEvent = FFI::Function.new(:void, [:pointer, :pointer], :blocking => true) do |ptr, event_ptr|
    #HandleEvent = Proc.new do |ptr, event_ptr|
      event = ::Pkg::Struct::Event.new(event_ptr)
      msg = ""

      case(event[:type])
        when :install_begin
          pkg = Pkg.new(event[:event][:install_begin][:pkg])
          handler.install_begin(pkg)
        when :install_finished
          pkg = Pkg.new(event[:event][:install_finished][:pkg])
          handler.install_finished(pkg)
        when :deinstall_begin
          pkg = Pkg.new(event[:event][:deinstall_begin][:pkg])
          handler.deinstall_begin(pkg)
        when :deinstall_finished
          pkg = Pkg.new(event[:event][:deinstall_finished][:pkg])
          handler.deinstall_finished(pkg)
        when :upgrade_begin
          pkg = Pkg.new(event[:event][:upgrade_begin][:pkg])
          handler.upgrade_begin(pkg)
        when :upgrade_finished
          pkg = Pkg.new(event[:event][:upgrade_finished][:pkg])
          handler.upgrade_finished(pkg)
        when :fetching
          url     = event[:event][:fetching][:url]
          total   = event[:event][:fetching][:total]
          done    = event[:event][:fetching][:done]
          elapsed = event[:event][:fetching][:elapsed]
          handler.fetching(url, total, done, elapsed)
        when :integritycheck_begin
          handler.integritycheck_begin()
        when :integritycheck_finished
          handler.integritycheck_finished()
        when :newpkgversion
          handler.newpkgversion()
        when :error
          handler.error(event[:event][:pkg_error][:msg])
        when :errno
          func = event[:event][:errno][:func]
          arg  = event[:event][:errno][:arg]
          handler.errno(func, arg)
        when :archive_comp_unsup
          handler.archive_comp_unsup()
        when :already_installed
          pkg = Pkg.new(event[:event][:already_installed][:pkg])
          handler.already_installed(pkg)
        when :failed_cksum
          handler.failed_cksum()
        when :create_db_error
          handler.create_db_error()
        when :required
          pkg   = Pkg.new(event[:event][:required][:pkg])
          force = event[:event][:required][:force]
          handler.required(pkg)
        when :missing_dep
          pkg_dep = event[:event][:_dep][:pkg_dep]
          name    = ::Pkg.pkg_dep_get(pkg_dep, Enum::DepAttr[:name])
          origin  = ::Pkg.pkg_dep_get(pkg_dep, Enum::DepAttr[:origin])
          version = ::Pkg.pkg_dep_get(pkg_dep, Enum::DepAttr[:version])
          handler.missing_dep(name, origin, version)
        when :noremotedb
          repo = event[:event][:remotedb][:repo]
          handler.noremotedb(repo)
        when :nolocaldb
          handler.nolocaldb()
        when :file_mismatch
          # TODO: Missing pkg_files binding
          #Pkg.new(event[:event][:file_mismatch][:pkg])
          #event[:event][:file_mismatch][:file]
          #event[:event][:file_mismatch][:newsum]
          #EventHandler.file_mismatch()
      end
    end

    def self.install
      ::Pkg.pkg_event_register(EventHandler::HandleEvent, ::FFI::Pointer::NULL)
    end

    private
    #Initialize a dummy handler
    def self.init
      h = Handler.new
      EventHandler.handler = h
      h
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
        if not Enum::Attributes[field].nil?
          args << Enum::Attributes
          args << Enum::Attributes[field]
          args << :pointer
          if Enum::Attributes[field] < ::Pkg::Enum::PKG_NUM_FIELDS
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
      raise "Couldn't initialize jobs" if res != Enum::Epkg[:ok]

      @jobs = jobs_ptr.read_pointer()

      ObjectSpace.define_finalizer @jobs, proc { Jobs.finalize(@jobs) }
    end

    def self.finalize(ptr)
      ::Pkg.pkg_jobs_free(ptr)
    end

    def add(pkg)
      res = ::Pkg.pkg_jobs_add(@jobs, pkg)
      raise "Couldn't add job" if res != Enum::Epkg[:ok]
    end

    def apply(force = false)
      flags = force ? 1 : 0
      res = ::Pkg.pkg_jobs_apply(@jobs, flags)
      raise "Couldn't apply jobs: #{Enum::Epkg[res]}" if res != Enum::Epkg[:ok]
    end
  end

  class Repo
    def initialize(name, packagesite)
      @name = name
      @packagesite = packagesite
    end

    def update
      res = ::Pkg.pkg_update(@name, @packagesite)

      raise "Update failed with return code : #{res}" if res != Enum::Epkg[:ok] and res != Enum::Epkg[:uptodate]
    end

    def inspect
      "#<Pkg::Repo #{@name} #{@packagesite}>"
    end

    def self.list
      Pkg.init()

      repos = []

      # Check if we need multirepos or not
      ptr = ::FFI::MemoryPointer.new(:bool)
      res = ::Pkg.pkg_config_bool(Enum::PkgConfig[:multirepos], ptr)
      raise "couldn't read config" if res != Enum::Epkg[:ok]

      multirepos = (ptr.read_bytes(1) == "\001")

      if multirepos
        repokv_ptr_ptr = ::FFI::MemoryPointer.new(:pointer)

        while (::Pkg.pkg_config_list(Enum::ConfigKey[:repos], repokv_ptr_ptr) == Enum::Epkg[:ok]) do
          repokv_ptr = repokv_ptr_ptr.read_pointer()

          name = ::Pkg.pkg_config_kv_get(repokv_ptr, Enum::KeyvalueType[:key])
          packagesite = ::Pkg.pkg_config_kv_get(repokv_ptr, Enum::KeyvalueType[:value])

          repos << Repo.new(name, packagesite)
        end
      else
        ptr = ::FFI::MemoryPointer.new(:pointer)
        res = ::Pkg.pkg_config_string(Enum::ConfigKey[:repo], ptr)
        raise "couldn't read config" if res != Enum::Epkg[:ok]

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

      raise "pkgdb_open failed: #{res}" if res != Enum::Epkg[:ok]

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
      :match => Enum::Match[:regex],
      :field => Enum::Field[:name],
      :reponame => "repo",
      :return => [:name],
      :force => false,
      :recursive => false
    }

    def search(pattern, opts={})
      options = SEARCH_DEFAULT.merge(opts)

      ary = []

      begin
        it_ptr = ::Pkg.pkgdb_search(@db_pointer, pattern, options[:match], options[:field], options[:reponame])
        # no results
        raise "Search returned NULL" if it_ptr.null?

        pkg_ptr = ::FFI::MemoryPointer.new(:pointer)

        while((res = ::Pkg.pkgdb_it_next(it_ptr, pkg_ptr, Enum::PkgLoad::BASIC)) == Enum::Epkg[:ok]) do
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

      package_ary = []
      packages.each do |pkg|
        package_ary << ::FFI::MemoryPointer.from_string(pkg)
      end
      package_ary << nil

      package_ptr = FFI::MemoryPointer.new(:pointer, package_ary.length)
      package_ary.each_with_index do |p, i|
        package_ptr[i].put_pointer(0, p)
      end

      it_ptr = ::Pkg.pkgdb_query_installs(@db_pointer, options[:match], packages.size(), package_ptr, options[:reponame], options[:force], options[:recursive])

      begin
        # no results
        raise "Search returned NULL" if it_ptr.null?

        pkg_ptr = ::FFI::MemoryPointer.new(:pointer)

        while((res = ::Pkg.pkgdb_it_next(it_ptr, pkg_ptr, Enum::PkgLoad::BASIC || Enum::PkgLoad::DEPS)) == Enum::Epkg[:ok]) do
          pkg = pkg_ptr.read_pointer()

          job.add(pkg)
          pkg = nil
        end
      ensure
        # Cleanup
        ::Pkg.pkgdb_it_free(it_ptr)
      end

      job
    end

  end
end
