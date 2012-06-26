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

  attach_function :pkgdb_open, [:pointer, DbType], :int

  # Args: 
  #   struct pkgdb *db, const char *pattern, match_t match, unsigned int field, const char * reponame
  # Return:
  #   pointer to pkgdb_it
  attach_function :pkgdb_search, [:pointer, :string, Match, :int, :string], :pointer

  #
  # int
  # pkgdb_it_next(struct pkgdb_it *it, struct pkg **pkg_p, int flags)
  attach_function :pkgdb_it_next, [:pointer, :pointer, :int], :int

  attach_function "pkg_get2", [:pointer, :varargs], :int

  class Pkg
    def self.init()
      @initialized ||= begin
        res = ::Pkg::pkg_init(nil)
        raise "pkg_init failed to initialize: #{res}" if res != 0

        true
      end
    end

    def self.read_string(ptr, field, output)
        value_ptr = ptr.read_pointer()
        raise "NULL pointer for pkg value" if value_ptr.null?

        value = value_ptr.read_string()
        output[field] = value
    end

    def self.read_uint64(ptr, field, output)
        value_ptr = ptr.read_pointer()
        raise "NULL pointer for pkg value" if value_ptr.null?

        value = value_ptr.read_double()
        output[field] = value
    end
    def self.read_bool(ptr, field, output)
        value_ptr = ptr.read_pointer()
        raise "NULL pointer for pkg value" if value_ptr.null?

        value = (value_ptr.read_bytes(1) == 0x00)
        output[field] = value
    end
    def self.read_license(ptr, field, output)
        value_ptr = ptr.read_pointer()
        raise "NULL pointer for pkg value" if value_ptr.null?

        value = License.from_native(value_ptr.read_byte(1))
        output[field] = value
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

  class Search
    def initialize(db_type = :default)
      ::Pkg::Pkg.init()

      db_ptr_ptr = FFI::MemoryPointer.new(:pointer)

      res = ::Pkg.pkgdb_open(db_ptr_ptr, db_type)

      if res != Epkg[:ok]
        raise "pkgdb_open failed: #{res}"
      end

      @db_pointer = db_ptr_ptr.read_pointer()
      raise "NULL pointer for db pointer" if @db_pointer.null?
    end

    SEARCH_DEFAULT = {
      :match => Match[:regex],
      :field => Field[:name],
      :reponame => "default",
      :return => [:name]
    }

    def search(pattern, opts={})
      options = SEARCH_DEFAULT.merge(opts)

      it_ptr = ::Pkg.pkgdb_search(@db_pointer, pattern, options[:match], options[:field], options[:reponame])

      # no results
      raise "Search returned NULL" if it_ptr.null?

      pkg_ptr = ::FFI::MemoryPointer.new(:pointer)

      ary = []

      while((res = ::Pkg.pkgdb_it_next(it_ptr, pkg_ptr, PkgLoad::BASIC)) == Epkg[:ok]) do
        pkg = pkg_ptr.read_pointer()

        ary << Pkg.get_pkg(pkg, options[:return])
      end

      ary
    end

  end
end
