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
end

class RecoveryCheckpointStore
  attr_reader :confirmed_uids, :marked_deleted_uids, :committed_uids

  def initialize(confirmed_uids: [], committed_uids: [])
    @confirmed_uids = confirmed_uids.dup
    @marked_deleted_uids = []
    @committed_uids = committed_uids.dup
  end

  def confirm_uid(uid)
    @confirmed_uids << uid unless @confirmed_uids.include?(uid)
  end

  def mark_uidl_deleted(uid)
    @marked_deleted_uids << uid unless @marked_deleted_uids.include?(uid)
  end

  def clear_deleted_marks
    @marked_deleted_uids.clear
  end

  def rollback_deleted_uids(uids)
    @marked_deleted_uids -= uids
  end

  def commit_deleted_uids(uids)
    uids.each do |uid|
      @committed_uids << uid unless @committed_uids.include?(uid)
    end
    clear_deleted_marks
  end
end

class RecoveryMailbox
  attr_accessor :messages
  attr_reader :marked_uids

  def initialize(messages)
    @messages = messages
    @marked_uids = []
  end

  def visible_messages
    @messages.reject {|uid, _| @marked_uids.include?(uid) }
  end

  def numbered_messages
    @messages.each_with_index.each_with_object({}) do |((uid, body), index), table|
      next if @marked_uids.include?(uid)

      table[index + 1] = [uid, body]
    end
  end

  def delete(uid)
    @marked_uids << uid
  end

  def reset
    @marked_uids.clear
  end

  def commit_deletions
    @messages.reject! {|uid, _| @marked_uids.include?(uid) }
    @marked_uids.clear
  end
end

class RecoveryCommand
  def initialize(mailbox, fault_retr: nil, fault_dele: nil,
                 fault_quit: nil, fault_uidl_mode: nil)
    @mailbox = mailbox
    @retr_fault = fault_retr
    @dele_fault = fault_dele
    @quit_fault = fault_quit
    @uidl_mode = fault_uidl_mode
    @dead = false
    @mailbox.reset
  end

  def uidl
    raise_if_dead
    raise Net::POPError, '-ERR UIDL unavailable' if @uidl_mode == :unavailable

    return {1 => 'duplicate', 2 => 'duplicate'} if @uidl_mode == :duplicate

    @mailbox.numbered_messages.each_with_object({}) do |(number, (uid, _)), table|
      table[number] = uid
    end
  end

  def retr(number)
    raise_if_dead
    uid, body = @mailbox.numbered_messages.fetch(number)
    if @retr_fault == uid
      @dead = true
      yield 'partial-content\r\n'
      raise EOFError, 'connection closed during RETR'
    end

    yield body
    '+OK'
  end

  def dele(number)
    raise_if_dead
    uid, = @mailbox.numbered_messages.fetch(number)
    @mailbox.delete(uid)
    if @dele_fault == uid
      @dead = true
      raise EOFError, 'connection closed during DELE'
    end
    '+OK marked'
  end

  def rset
    raise_if_dead
    @mailbox.reset
    '+OK'
  end

  def quit
    raise_if_dead
    if @quit_fault
      @dead = true
      raise EOFError, 'connection closed during QUIT'
    end
    @mailbox.commit_deletions
    '+OK bye'
  end

  private

  def raise_if_dead
    raise IOError, 'POP command is no longer usable' if @dead
  end
end

class RecoverySocket
  def closed?
    false
  end

  def close
  end
end

class TestRecoverablePOP < Test::Unit::TestCase
  def test_recovers_after_retr_interruption_with_changed_message_numbers
    mailbox = RecoveryMailbox.new([
      ['uid-a', "message-a\r\n"],
      ['uid-b', "message-b\r\n"]
    ])
    store = RecoveryCheckpointStore.new

    pop, session = connect_recovery(mailbox, store, fault_retr: 'uid-b')
    assert_equal 'message-a' + "\r\n", session.receive('uid-a')
    assert_raise(EOFError, IOError) { session.receive('uid-b') }
    assert_equal ['uid-a'], store.confirmed_uids
    close_recovery(pop)

    mailbox.messages.unshift(['uid-new', "new-mail\r\n"])

    pop, session = connect_recovery(mailbox, store)
    result = session.reconcile!
    assert_predicate result, :success?
    assert_equal ['uid-new', 'uid-b'], session.each_pending.map(&:uidl)
    assert_equal 'message-b' + "\r\n", session.receive('uid-b')
    assert_empty store.marked_deleted_uids
    delete_result = session.delete_confirmed
    assert_equal ['uid-a', 'uid-b'], delete_result.uids
    finish_result = session.finish
    close_recovery(pop)

    assert_equal [['uid-new', "new-mail\r\n"]], mailbox.messages
    assert_equal ['uid-a', 'uid-b'], finish_result.uids
    assert_equal ['uid-a', 'uid-b'], store.committed_uids
  end

  def test_recovers_after_dele_interruption_with_changed_message_numbers
    mailbox = RecoveryMailbox.new([
      ['uid-a', "message-a\r\n"],
      ['uid-b', "message-b\r\n"]
    ])
    store = RecoveryCheckpointStore.new(confirmed_uids: ['uid-a', 'uid-b'])

    pop, session = connect_recovery(mailbox, store, fault_dele: 'uid-b')
    session.delete_confirmed rescue nil
    close_recovery(pop)

    assert_empty store.marked_deleted_uids
    assert_equal 2, mailbox.messages.size
    mailbox.messages.unshift(['uid-new', "new-mail\r\n"])

    pop, session = connect_recovery(mailbox, store)
    session.delete_confirmed
    result = session.finish
    close_recovery(pop)

    assert_equal [['uid-new', "new-mail\r\n"]], mailbox.messages
    assert_equal ['uid-a', 'uid-b'], result.uids
    assert_equal ['uid-a', 'uid-b'], store.committed_uids
  end

  def test_recovers_after_quit_interruption_with_changed_message_numbers
    mailbox = RecoveryMailbox.new([
      ['uid-a', "message-a\r\n"],
      ['uid-b', "message-b\r\n"]
    ])
    store = RecoveryCheckpointStore.new(confirmed_uids: ['uid-a', 'uid-b'])

    pop, session = connect_recovery(mailbox, store, fault_quit: true)
    session.delete_confirmed
    assert_equal ['uid-a', 'uid-b'], store.marked_deleted_uids
    assert_equal 2, mailbox.messages.size
    assert_raise(EOFError, IOError) { session.finish }
    close_recovery(pop)

    assert_empty store.marked_deleted_uids
    assert_empty store.committed_uids
    assert_equal 2, mailbox.messages.size
    mailbox.messages.unshift(['uid-new', "new-mail\r\n"])

    pop, session = connect_recovery(mailbox, store)
    session.delete_confirmed
    result = session.finish
    close_recovery(pop)

    assert_equal [['uid-new', "new-mail\r\n"]], mailbox.messages
    assert_equal ['uid-a', 'uid-b'], result.uids
    assert_equal ['uid-a', 'uid-b'], store.committed_uids
  end

  def test_rset_clears_marks_only_after_server_accepts_it
    mailbox = RecoveryMailbox.new([
      ['uid-a', "message-a\r\n"],
      ['uid-b', "message-b\r\n"]
    ])
    store = RecoveryCheckpointStore.new(confirmed_uids: ['uid-a'])
    pop, session = connect_recovery(mailbox, store)

    session.delete_confirmed
    assert_equal ['uid-a'], store.marked_deleted_uids
    assert session.reset
    assert_empty store.marked_deleted_uids
    pop.finish
    close_recovery(pop)

    assert_equal 2, mailbox.messages.size
    assert_empty store.committed_uids
  end

  def test_reconciliation_reports_uidl_unavailable
    mailbox = RecoveryMailbox.new([['uid-a', 'a']])
    store = RecoveryCheckpointStore.new
    pop, session = connect_recovery(mailbox, store,
                                    fault_uidl_mode: :unavailable)

    result = session.reconcile!
    assert_equal :uidl_unavailable, result.status
    error = assert_raise(Net::POP3::RecoverableSession::Error) do
      session.each_pending.to_a
    end
    assert_equal result, error.result
    close_recovery(pop)
  end

  def test_streaming_retrieval_does_not_confirm_or_delete
    mailbox = RecoveryMailbox.new([['uid-a', "message-a\r\n"]])
    store = RecoveryCheckpointStore.new
    pop, session = connect_recovery(mailbox, store)
    chunks = []

    result = session.retrieve('uid-a') do |chunk|
      chunks << chunk
    end

    assert_nil result
    assert_equal ["message-a\r\n"], chunks
    assert_empty store.confirmed_uids
    assert_empty store.marked_deleted_uids
    close_recovery(pop)
  end

  def test_reconciliation_reports_duplicate_uidls
    mailbox = RecoveryMailbox.new([
      ['duplicate', 'a'], ['duplicate', 'b']
    ])
    store = RecoveryCheckpointStore.new
    pop, session = connect_recovery(mailbox, store,
                                    fault_uidl_mode: :duplicate)

    result = session.reconcile!
    assert_equal :duplicate_uidl, result.status
    assert_equal ['duplicate'], result.duplicate_uids
    close_recovery(pop)
  end

  def test_reconciliation_reports_confirmed_mail_disappeared
    mailbox = RecoveryMailbox.new([['uid-a', 'a']])
    store = RecoveryCheckpointStore.new(confirmed_uids: ['uid-missing'])
    pop, session = connect_recovery(mailbox, store)

    result = session.reconcile!
    assert_equal :missing_confirmed_uidl, result.status
    assert_equal ['uid-missing'], result.missing_confirmed_uids
    close_recovery(pop)
  end

  private

  def connect_recovery(mailbox, store, fault_retr: nil, fault_dele: nil,
                       fault_quit: nil, fault_uidl_mode: nil)
    pop = Net::POP3.new('127.0.0.1', 110)
    command = RecoveryCommand.new(
      mailbox,
      fault_retr: fault_retr,
      fault_dele: fault_dele,
      fault_quit: fault_quit,
      fault_uidl_mode: fault_uidl_mode
    )
    pop.instance_variable_set(:@started, true)
    pop.instance_variable_set(:@command, command)
    pop.instance_variable_set(:@socket, RecoverySocket.new)
    [pop, pop.recoverable_session(store)]
  end

  def close_recovery(pop)
    pop.send(:close_connection)
  end
end
