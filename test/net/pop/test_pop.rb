# frozen_string_literal: true
require 'net/pop'
require 'test/unit'
require 'digest/md5'

class TestPOP < Test::Unit::TestCase
  def setup
    @users = {'user' => 'pass', 'möter' => 'päss' }
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

  def test_utf8_user_auth
    commands = pop_test(false, utf8_capa: true) do |pop|
      pop.start('möter', @users['möter'], utf8: true)
      assert_predicate pop, :utf8?
      assert_predicate pop, :utf8_user?
    end

    assert_equal [
      "CAPA\r\n".b,
      "UTF8 ON\r\n".b,
      "USER m\xC3\xB6ter\r\n".b,
      "PASS p\xC3\xA4ss\r\n".b,
    ], commands
  end

  def test_utf8_mode_does_not_send_utf8_user_for_ascii_account
    commands = pop_test(false, utf8_capa: true) do |pop|
      pop.start(@ok_user, @users[@ok_user], utf8: true)
    end

    assert_equal [
      "CAPA\r\n".b,
      "UTF8 ON\r\n".b,
      "USER user\r\n".b,
      "PASS pass\r\n".b,
    ], commands
  end

  def test_non_ascii_user_requires_utf8_user_capability
    commands = pop_test(false, utf8_capa: :utf8) do |pop|
      error = assert_raise Net::POPUTF8Error do
        pop.start('möter', @users['möter'], utf8: true)
      end
      assert_equal 'POP3 UTF8 USER capability is required for UTF-8 accounts',
                   error.message
    end

    assert_equal ["CAPA\r\n".b, "UTF8 ON\r\n".b], commands
  end

  def test_server_rejection_preserves_reason
    commands = pop_test(false, reject_utf8: true) do |pop|
      error = assert_raise Net::POPUTF8Error do
        pop.start(@ok_user, @users[@ok_user], utf8: true)
      end
      assert_equal '-ERR UTF8 unavailable: policy', error.message
    end

    assert_equal ["CAPA\r\n".b, "UTF8 ON\r\n".b], commands
  end

  def test_invalid_utf8_account_does_not_negotiate
    commands = pop_test(false, utf8_capa: true) do |pop|
      assert_raise Encoding::InvalidByteSequenceError do
        pop.start("m\xffter".b, 'pass', utf8: true)
      end
    end

    assert_empty commands
  end

  def test_invalid_utf8_password_does_not_negotiate
    commands = pop_test(false, utf8_capa: true) do |pop|
      assert_raise Encoding::InvalidByteSequenceError do
        pop.start(@ok_user, "p\xffss".b, utf8: true)
      end
    end

    assert_empty commands
  end

  def test_default_login_does_not_negotiate_utf8
    commands = pop_test(false, utf8_capa: true) do |pop|
      pop.start(@ok_user, @users[@ok_user])
    end

    assert_equal [
      "USER user\r\n".b,
      "PASS pass\r\n".b,
    ], commands
  end

  def test_apop_digest_semantics_are_unchanged_with_utf8_mode
    commands = pop_test(@stamp_base, utf8_capa: true) do |pop|
      pop.start(@ok_user, @users[@ok_user], utf8: true)
    end

    digest = Digest::MD5.hexdigest("<#{@stamp_base}>#{@users[@ok_user]}")
    assert_equal [
      "CAPA\r\n".b,
      "UTF8 ON\r\n".b,
      "APOP user #{digest}\r\n".b,
    ], commands
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
    assert_equal Encoding::ASCII_8BIT, res.encoding

    res = popmail.top(1)
    assert_equal "[ruby-core:85210]\r\n", res
    assert_not_predicate res, :frozen?
    assert_equal Encoding::ASCII_8BIT, res.encoding
  end

  def test_popmail_preserves_raw_utf8_bytes
    raw = "Subject: ä\r\n\r\n\xff\r\n".b
    command = Object.new
    def command.retr(_number)
      yield "Subject: ä\r\n".b
      yield "\r\n".b
      yield "\xff\r\n".b
    end
    def command.top(_number, _lines)
      yield "Subject: ä\r\n".b
      yield "\xff\r\n".b
    end

    popmail = Net::POPMail.new(1, raw.bytesize, :unused, command)
    res = popmail.pop

    assert_equal raw, res
    assert_equal Encoding::ASCII_8BIT, res.encoding
    res = popmail.top(0)
    assert_equal "Subject: ä\r\n\xff\r\n".b, res
    assert_equal Encoding::ASCII_8BIT, res.encoding
  end

  def pop_test(apop=false, utf8_capa: false, reject_utf8: false)
    host = 'localhost'
    server = TCPServer.new(host, 0)
    port = server.addr[1]
    commands = []
    server_thread = Thread.start do
      sock = server.accept
      begin
        pop_server_loop(sock, apop, utf8_capa: utf8_capa,
                        reject_utf8: reject_utf8, commands: commands)
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
    commands
  end

  def pop_server_loop(sock, apop, utf8_capa: false, reject_utf8: false,
                      commands: nil)
    if apop
      sock.print "+OK ready <#{apop}>\r\n"
    else
      sock.print "+OK ready\r\n"
    end
    user = nil
    while line = sock.gets
      commands << line.b if commands
      case line
      when /^CAPA\r\n/
        sock.print "+OK Capability list follows\r\n"
        if utf8_capa == :utf8
          sock.print "UTF8\r\n"
        elsif utf8_capa
          sock.print "UTF8 USER\r\n"
        end
        sock.print ".\r\n"
      when /^UTF8 ON\r\n/
        if reject_utf8
          sock.print "-ERR UTF8 unavailable: policy\r\n"
        else
          sock.print "+OK UTF8 enabled\r\n"
        end
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
end
