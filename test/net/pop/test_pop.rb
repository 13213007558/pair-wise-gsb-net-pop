# frozen_string_literal: true
require 'net/pop'
require 'test/unit'
require 'digest/md5'

class TestPOP < Test::Unit::TestCase
  def setup
    @users = {'user' => 'pass' }
    @ok_user = 'user'
    @stamp_base = "#{$$}.#{Time.now.to_i}@localhost"
  end

  def test_pop_auth_ok
    pop_test(false) do |pop|
      assert_instance_of Net::POP3, pop
      assert_nothing_raised do
        pop.start(@ok_user, @users[@ok_user])
      end
    end
  end

  def test_pop_auth_ng
    pop_test(false) do |pop|
      assert_instance_of Net::POP3, pop
      assert_raise Net::POPAuthenticationError do
        pop.start(@ok_user, 'bad password')
      end
    end
  end

  def test_apop_ok
    pop_test(@stamp_base) do |pop|
      assert_instance_of Net::APOP, pop
      assert_nothing_raised do
        pop.start(@ok_user, @users[@ok_user])
      end
    end
  end

  def test_apop_ng
    pop_test(@stamp_base) do |pop|
      assert_instance_of Net::APOP, pop
      assert_raise Net::POPAuthenticationError do
        pop.start(@ok_user, 'bad password')
      end
    end
  end

  def test_apop_invalid
    pop_test("\x80"+@stamp_base) do |pop|
      assert_instance_of Net::APOP, pop
      assert_raise Net::POPAuthenticationError do
        pop.start(@ok_user, @users[@ok_user])
      end
    end
  end

  def test_apop_invalid_at
    pop_test(@stamp_base.sub('@', '.')) do |pop|
      assert_instance_of Net::APOP, pop
      assert_raise Net::POPAuthenticationError do
        pop.start(@ok_user, @users[@ok_user])
      end
    end
  end

  def test_pop_user_crlf_injection
    pop_test(false) do |pop|
      assert_raise ArgumentError do
        pop.start("user\r\nDELE 1", @users[@ok_user])
      end
    end
  end

  def test_pop_pass_crlf_injection
    pop_test(false) do |pop|
      assert_raise ArgumentError do
        pop.start(@ok_user, "pass\r\nDELE 1")
      end
    end
  end

  def test_apop_crlf_injection
    pop_test(@stamp_base) do |pop|
      assert_raise ArgumentError do
        pop.start("user\r\nDELE 1", @users[@ok_user])
      end
    end
  end

  def test_utf8_auth_sends_utf8_command_before_user
    socket = FakePOP3Socket.new(['+OK', '+OK', '+OK', '+OK'])
    command = Net::POP3Command.new(socket)

    command.enable_utf8
    command.auth('tüst@example.test', 'päss', utf8: true)

    expected_commands = ["UTF8\r\n",
                         "USER tüst@example.test\r\n",
                         "PASS päss\r\n"]
    expected_commands.map!(&:b)
    assert_equal expected_commands, socket.commands
    assert_equal Encoding::BINARY, socket.commands[1].encoding
  end

  def test_utf8_user_capa_does_not_select_utf8_mode
    responses = ['+OK', '+OK', "USER\r\n", "UTF8 USER\r\n", ".\r\n",
                 '+OK', '+OK']
    socket = FakePOP3Socket.new(responses)
    command = Net::POP3Command.new(socket)

    assert_include command.capa, 'utf8 user'
    command.auth('tüst@example.test', 'päss', utf8_user: true)

    expected_commands = ["CAPA\r\n",
                         "USER tüst@example.test\r\n",
                         "PASS päss\r\n"]
    expected_commands.map!(&:b)
    assert_equal expected_commands, socket.commands
  end

  def test_utf8_rejection_preserves_server_reason
    socket = FakePOP3Socket.new(['+OK', '-ERR UTF8 unavailable',
                                 '+OK', '+OK'])
    command = Net::POP3Command.new(socket)

    error = assert_raise Net::POPUTF8Error do
      command.enable_utf8
    end
    assert_equal '-ERR UTF8 unavailable', error.response
    assert_equal ["UTF8\r\n"], socket.commands

    command.auth('traditional-user', 'pass')
    expected_commands = ["UTF8\r\n",
                         "USER traditional-user\r\n",
                         "PASS pass\r\n"]
    assert_equal expected_commands, socket.commands
  end

  def test_utf8_invalid_account_is_rejected_before_command
    socket = FakePOP3Socket.new(['+OK'])
    command = Net::POP3Command.new(socket)

    assert_raise ArgumentError do
      command.auth("bad\xffuser", 'pass', utf8: true)
    end
    assert_empty socket.commands

    pop = Net::POP3.new('pop.example.test')
    assert_raise ArgumentError do
      pop.start("bad\xffuser", 'pass', utf8: true)
    end
  end

  def test_default_auth_does_not_transcode_account
    socket = FakePOP3Socket.new(['+OK', '+OK', '+OK'])
    command = Net::POP3Command.new(socket)
    account = "t\xfcst".dup.force_encoding(Encoding::ISO_8859_1)

    command.auth(account, 'pass')

    expected_commands = ["USER t\xfcst\r\n", "PASS pass\r\n"]
    expected_commands.map!(&:b)
    assert_equal expected_commands, socket.commands
  end

  def test_retr_and_top_return_original_bytes
    message = ["Subject: =?UTF-8?B?d\xc3\xbcst?=\r\n",
               "\x80\xff\r\n",
               "..kept-as-dot\r\n",
               ".\r\n"]
    retr_socket = FakePOP3Socket.new(['+OK', "+OK\r\n"].concat(message))
    retr_command = Net::POP3Command.new(retr_socket)
    retr_result = +''
    retr_command.retr(1) { |chunk| retr_result << chunk }
    expected_message = "Subject: =?UTF-8?B?d\xc3\xbcst?=\r\n\x80\xff\r\n.kept-as-dot\r\n".b
    assert_equal expected_message,
                 retr_result
    assert_equal Encoding::BINARY, retr_result.encoding

    top_socket = FakePOP3Socket.new(['+OK', "+OK\r\n"].concat(message))
    top_command = Net::POP3Command.new(top_socket)
    top_result = +''
    top_command.top(1, 2) { |chunk| top_result << chunk }
    assert_equal expected_message,
                 top_result
    assert_equal Encoding::BINARY, top_result.encoding
  end

  def test_apop_digest_uses_challenge_and_password_octets
    stamp = 'stamp@example.test'
    socket = FakePOP3Socket.new(["+OK ready <#{stamp}>", '+OK'])
    command = Net::POP3Command.new(socket)
    password = "p\xe4ss".dup.force_encoding(Encoding::ISO_8859_1)

    command.apop('user', password)

    digest = Digest::MD5.hexdigest("<#{stamp}>" + password)
    assert_equal ["APOP user #{digest}\r\n"], socket.commands
  end

  def test_utf8_mode_is_selected_before_apop_without_rewriting_digest
    stamp = 'stamp@example.test'
    socket = FakePOP3Socket.new(["+OK ready <#{stamp}>", '+OK', '+OK'])
    command = Net::POP3Command.new(socket)

    command.enable_utf8
    command.apop('user', 'pass')

    digest = Digest::MD5.hexdigest("<#{stamp}>pass")
    assert_equal ["UTF8\r\n", "APOP user #{digest}\r\n"],
                 socket.commands
  end

  def test_utf8_user_is_rejected_for_apop_before_connecting
    pop = Net::APOP.new('pop.example.test')

    assert_raise ArgumentError do
      pop.start('user', 'pass', utf8_user: true)
    end
  end

  def test_popmail_preserves_binary_message_defaults
    command = Object.new
    data = "Subject: =?UTF-8?B?d\xc3\xbcst?=\r\n\x80\xff\r\n".b

    def command.retr(_number)
      yield "Subject: =?UTF-8?B?d\xc3\xbcst?=\r\n".b
      yield "\x80\xff\r\n".b
    end

    def command.top(_number, _lines)
      yield "Subject: =?UTF-8?B?d\xc3\xbcst?=\r\n".b
      yield "\x80\xff\r\n".b
    end

    mail = Net::POPMail.new(1, data.bytesize, nil, command)

    assert_equal data, mail.pop
    assert_equal Encoding::BINARY, mail.pop.encoding
    assert_equal data, mail.top(0)
    assert_equal Encoding::BINARY, mail.top(0).encoding
  end

  def test_popmail
    # totally not representative of real messages, but
    # enough to test frozen bugs
    lines = [ "[ruby-core:85210]" , "[Bug #14416]" ].freeze
    command = Object.new
    command.instance_variable_set(:@lines, lines)

    def command.retr(n)
      @lines.each { |l| yield "#{l}\r\n" }
    end

    def command.top(number, nl)
      @lines.each do |l|
        yield "#{l}\r\n"
        break if (nl -= 1) <= 0
      end
    end

    net_pop = :unused
    popmail = Net::POPMail.new(1, 123, net_pop, command)
    res = popmail.pop
    assert_equal "[ruby-core:85210]\r\n[Bug #14416]\r\n", res
    assert_not_predicate res, :frozen?

    res = popmail.top(1)
    assert_equal "[ruby-core:85210]\r\n", res
    assert_not_predicate res, :frozen?
  end

  def pop_test(apop=false)
    host = 'localhost'
    server = TCPServer.new(host, 0)
    port = server.addr[1]
    server_thread = Thread.start do
      sock = server.accept
      begin
        pop_server_loop(sock, apop)
      ensure
        sock.close
      end
    end
    client_thread = Thread.start do
      begin
        begin
          pop = Net::POP3::APOP(apop).new(host, port)
          #pop.set_debug_output $stderr
          yield pop
        ensure
          begin
            pop.finish
          rescue IOError
            raise unless $!.message == "POP session not yet started"
          end
        end
      ensure
        server.close
      end
    end
    assert_join_threads([client_thread, server_thread])
  end

  def pop_server_loop(sock, apop)
    if apop
      sock.print "+OK ready <#{apop}>\r\n"
    else
      sock.print "+OK ready\r\n"
    end
    user = nil
    while line = sock.gets
      case line
      when /^USER (.+)\r\n/
        user = $1
        if @users.key?(user)
          sock.print "+OK\r\n"
        else
          sock.print "-ERR unknown user\r\n"
        end
      when /^PASS (.+)\r\n/
        if @users[user] == $1
          sock.print "+OK\r\n"
        else
          sock.print "-ERR invalid password\r\n"
        end
      when /^APOP (.+) (.+)\r\n/
        user = $1
        if apop && Digest::MD5.hexdigest("<#{apop}>#{@users[user]}") == $2
          sock.print "+OK\r\n"
        else
          sock.print "-ERR authentication failed\r\n"
        end
      when /^QUIT/
        sock.print "+OK bye\r\n"
        return
      else
        sock.print "-ERR command not recognized\r\n"
        return
      end
    end
  end

  class FakePOP3Socket
    attr_reader :commands

    def initialize(responses)
      @read_buffer = +''
      responses.each do |response|
        @read_buffer << response
        @read_buffer << "\n" unless response.end_with?("\n")
      end
      @commands = []
    end

    def writeline(line)
      write_nonblock(line + "\r\n")
    end

    def write_nonblock(line, exception: true)
      @commands << line.dup.force_encoding(Encoding::BINARY)
      line.bytesize
    end

    def readline
      readuntil("\n").chop
    end

    def read_nonblock(maxlen, buffer = nil, exception: true)
      chunk = @read_buffer.byteslice(0, maxlen)
      @read_buffer = @read_buffer.byteslice(maxlen, @read_buffer.bytesize) || +''
      if chunk.nil? || chunk.empty?
        return nil unless exception
        raise EOFError, 'end of file reached'
      end
      if buffer
        buffer.replace(chunk.b)
        buffer
      else
        chunk.b
      end
    end

    def each_message_chunk
      while (line = readuntil("\r\n")) != ".\r\n"
        yield line.delete_prefix('.')
      end
    end

    def each_list_item
      while (line = readuntil("\r\n")) != ".\r\n"
        yield line.chop
      end
    end

    def read_timeout=(_)
    end

    def closed?
      false
    end

    def close
    end

    def to_io
      self
    end

    def wait_readable(_)
      true
    end

    def wait_writable(_)
      true
    end

    private

    def readuntil(terminator)
      index = @read_buffer.index(terminator)
      raise EOFError, 'end of file reached' unless index

      line = @read_buffer.byteslice(0, index + terminator.bytesize)
      rest = index + terminator.bytesize
      @read_buffer = @read_buffer.byteslice(rest, @read_buffer.bytesize) || +''
      line.b
    end
  end
end
