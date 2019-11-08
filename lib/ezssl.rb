require 'openssl'
require 'socket'
module EzSSL
  class Server
    attr_reader :read
    def initialize(ip,port,length=2048)
      @socket=TCPServer.open(ip,port)
      @pair=OpenSSL::PKey::RSA.new(length)
      @pubkey=@pair.public_key
      @read=@pubkey.public_encrypt('hello').length
    end
    def accept()
      client=@socket.accept
      client.puts @pubkey.to_s
      go=true
      key=''
      while go
        msg=client.gets
        key+=msg
        go=false if msg=="-----END PUBLIC KEY-----\n"
      end
      return Handle.new(client,key,self)
    end
    def decrypt(msg)
      return @pair.private_decrypt(msg)
    end
  end

  class Client
    def initialize(ip,port,length=2048)
      @pair=OpenSSL::PKey::RSA.new(length)
      @pubkey=@pair.public_key
      @socket=TCPSocket.new(ip,port)
      @read=@pubkey.public_encrypt('hello').length
      go=true
      key=''
      while go
        msg=@socket.gets
        key+=msg
        go=false if msg=="-----END PUBLIC KEY-----\n"
      end
      @socket.puts @pubkey.to_s
      @key=OpenSSL::PKey::RSA.new(key)
    end
    def puts(msg)
      @socket.write @key.public_encrypt(msg)
      return nil
    end
    def gets()
      msg=@socket.read(@read)
      return @pair.private_decrypt(msg)
    end
  end

  private
  class Handle
    def initialize(client,key,server)
      @client=client
      @key=OpenSSL::PKey::RSA.new(key)
      @server=server
    end
    def puts(msg)
      @client.write @key.public_encrypt(msg)
    end
    def gets()
      msg=@client.read(@server.read)
      return @server.decrypt(msg)
    end
    def close
      @client.close
    end
  end
end
