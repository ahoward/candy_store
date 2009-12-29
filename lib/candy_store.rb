#
# NAME
#   CandyStore
#
# SYNOPSIS
#   hybrid session store that combines rails' built-in cookie based session
#   store with its database backed one
#
#     session              # normal rails' cookie based session
#     session.flash        # same as above 
#     session.server       # this one lives in the db 
#     session.server.flash # this one lives in the db too
#
# URI
#   http://github.com/ahoward/candy_store
#
# USAGE
#
#   1) drop this file in lib/candy_store.rb
#
#   2) run the migration to create the database table
#
#      . rake db:sessions:create
#      . rake db:migrate
#
#   3) create config/initializers/session_store.rb with contents like 
#
#        ActionController::Base.session_store = CandyStore
#
#      (or put that in config/environment.rb)
#
#   4) use sessions normally.  if you need to store large items or otherwise
#   want to put some infomation in the db use
#
#       session.server
#       session.server.flash
#
#   that's it!
#


module ActionController
  module Session
    class CandyStore < CookieStore
      def call(env)
        session_hash = AbstractStore::SessionHash.new(self, env)
        session_hash.extend(ServerSide::SessionPowers)  # this is the only modification to CookieStore

        options = @default_options.dup

        env[ENV_SESSION_KEY] = session_hash
        env[ENV_SESSION_OPTIONS_KEY] = options

        status, headers, body = @app.call(env)

        session_data = env[ENV_SESSION_KEY]
        options = env[ENV_SESSION_OPTIONS_KEY]

        if !session_data.is_a?(AbstractStore::SessionHash) || session_data.send(:loaded?) || options[:expire_after]
          session_data.send(:load!) if session_data.is_a?(AbstractStore::SessionHash) && !session_data.send(:loaded?)
          session_data = marshal(session_data.to_hash)

          raise CookieOverflow if session_data.size > MAX

          cookie = Hash.new
          cookie[:value] = session_data
          unless options[:expire_after].nil?
            cookie[:expires] = Time.now + options[:expire_after]
          end

          cookie = build_cookie(@key, cookie.merge(options))
          unless headers[HTTP_SET_COOKIE].blank?
            headers[HTTP_SET_COOKIE] << "\n#{cookie}"
          else
            headers[HTTP_SET_COOKIE] = cookie
          end
        end

        session_hash.save_server_flash! if session_hash.server_flash?
        session_hash.save_server_data! if session_hash.server_data?

        [status, headers, body]
      end

  # this module/extension gives the cookie store access to a parallel db
  # backend session
  #
      module ServerSide
        module SessionPowers
          def client
            self
          end

          def server
            unless defined?(@server_data)
              @server_data = Data.for(session_id)
            end
            unless defined?(@server_hash)
              @server_hash = @server_data.data
              @server_hash.extend(FlashPowers)
            end
            return @server_hash
          end

          def session_id
            self[:session_id] || self['session_id'] || @env[ENV_SESSION_OPTIONS_KEY][:id] # soon to be depricated?
          end

          def server_data?
            defined?(@server_data) and defined?(@server_hash) and @server_data and @server_hash
          end

          def save_server_data!
            if server_data?
              session_id = ((@server_hash['session_id'] || @server_hash[:session_id] || @server_hash.session_id) rescue nil)
              @server_data.data = @server_hash
              @server_data.session_id ||= session_id
              @server_data.save if @server_data.session_id
            end
          end

          def destroy_server_data!
            server unless server_data?
            if server_data?
              @server_data.destroy
            end
          end

          def server_flash?
            defined?(@server_hash) and @server_hash and @server_hash.flash?
          end

          def save_server_flash!
            if server_flash?
              @server_hash.save_flash!
            end
          end

          module FlashPowers
            FlashHash = ::ActionController::Flash::FlashHash unless defined?(FlashHash)

             
            def flash
              unless flash?
                session = self
                @flash = session["flash"] || FlashHash.new
                @flash.sweep
              end
              @flash
            end

            def flash?
              defined?(@flash)
            end

            def save_flash!
              session = self
              @flash.store(session)
              remove_instance_variable(:@flash)
            end
          end
        end

        class Data < ::ActiveRecord::Base
          set_table_name :sessions

          class << Data
            def for(session_id)
              silence do
                find_by_session_id(session_id) or
                new(:session_id => session_id, :data => Hash.new)
              end
            end
          end
          
          def data
            data = self['data']
            Marshal.load(ActiveSupport::Base64.decode64(data)) if data
          end

          def data=(data)
            self['data'] = ActiveSupport::Base64.encode64(Marshal.dump(data)) if data
          end

          def save(*args, &block)
            Data.silence{ super }
          end
        end
      end
    end
  end
end

CandyStore = ActionController::Session::CandyStore
 
