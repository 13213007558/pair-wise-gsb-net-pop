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

class ResumableCheckpoint
  def initialize(confirmed: [], contents: {})
    @downloaded = []
    @confirmed = confirmed.dup
    @deletion_pending = []
    @deleted = []
    @contents = contents
    @mutex = Mutex.new
  end

  attr_reader :contents

  def confirmed_uids
    @mutex.synchronize { @confirmed.dup }
  end

  def downloaded?(uid)
    @mutex.synchronize { @downloaded.include?(uid) }
  end

  def mark_downloaded(uid)
    @mutex.synchronize { @downloaded << uid unless @downloaded.include?(uid) }
  end

  def confirm(uid)
    @mutex.synchronize do
      @confirmed << uid unless @confirmed.include?(uid)
    end
  end

  def downloaded_uids
    @mutex.synchronize { @downloaded.dup }
  end

  def deletion_pending_uids
    @mutex.synchronize { @deletion_pending.dup }
  end

  def deleted_uids
    @mutex.synchronize { @deleted.dup }
  end

  def mark_deletion_requested(uid)
    @mutex.synchronize do
      @deletion_pending << uid unless @deletion_pending.include?(uid)
    end
  end

  def rollback_deletion_requests(uids)
    @mutex.synchronize { @deletion_pending -= uids }
  end

  def mark_deletion_committed(uids)
    @mutex.synchronize do
      @deletion_pending -= uids
      @confirmed -= uids
      @deleted.concat(uids - @deleted)
    end
  end
end

class FakePOPMail
  def initialize(number, uid, content, connection)
    @number = number
    @uid = uid
    @content = content
    @connection = connection
  end

  attr_accessor :uid
  attr_reader :number

  def length
    @content.bytesize
  end

  alias size length

  def unique_id
    @uid
  end

  def pop
    @connection.record("RETR #{@number}")
    if @connection.fault?(:retr)
      yield @content[0, 5]
      raise EOFError, 'RETR interrupted'
    end
    yield @content
  end

  def delete
    @connection.record("DELE #{@number}")
    @connection.dele(@number)
  end
end

class FakePOP3
  def initialize(server, attempt, faults, uidl_mode)
    @server = server
    @attempt = attempt
    @faults = faults
    @uidl_mode = uidl_mode
    @marked = []
    @started = true
    @interrupted_after_dele = false
  end

  attr_reader :attempt

  def started?
    @started
  end

  def mails
    @server.messages.each_with_index.map do |(uid, content), index|
      FakePOPMail.new(index + 1, uid, content, self)
    end
  end

  def uidl_table
    raise Net::POPError, '-ERR UIDL unsupported' if @uidl_mode == :error
    table = {}
    @server.messages.each_with_index do |(uid, _), index|
      table[index + 1] = @uidl_mode == :duplicate ? 'dup' : uid
    end
    table
  end

  def dele(number)
    uid = @server.uid_at(number)
    @marked << uid
    if fault?(:dele)
      @interrupted_after_dele = true
    end
    '+OK marked'
  end

  def reset
    record('RSET')
    @marked.clear
    '+OK reset'
  end

  def quit
    record('QUIT')
    raise EOFError, 'connection closed before QUIT' if @interrupted_after_dele
    if fault?(:quit)
      @server.commit_if_would_have(@marked)
      raise EOFError, 'QUIT interrupted'
    end
    @server.commit(@marked)
    @started = false
    '+OK bye'
  end

  def finish
    @started = false
    '+OK bye'
  end

  def abort
    @started = false
  end

  def fault?(command)
    @faults.include?([@attempt, command])
  end

  def record(command)
    @server.record(@attempt, command)
  end
end

class FakePOP3Server
  def initialize(faults: [], uidl_mode: :normal)
    @faults = faults
    @uidl_mode = uidl_mode
    @mailbox = initial_mailbox(uidl_mode)
    @attempts = 0
    @commands = []
  end

  attr_reader :commands

  def connect
    @attempts += 1
    FakePOP3.new(self, @attempts, @faults, @uidl_mode)
  end

  def record(attempt, command)
    @commands << [attempt, command]
  end

  def messages
    @mailbox.to_a
  end

  def uid_at(number)
    messages.dig(number - 1, 0)
  end

  def commit(uids)
    uids.each { |uid| @mailbox.delete(uid) }
  end

  def commit_if_would_have(uids)
    commit(uids)
  end

  def committed_uids
    @mailbox.keys
  end

  def add_mail_at_front(uid, content)
    existing = @mailbox.to_a
    @mailbox = {uid => content}
    existing.each { |old_uid, old_content| @mailbox[old_uid] = old_content }
  end

  def shutdown
  end

  private

  def initial_mailbox(uidl_mode)
    old = {'uid-old' => "Subject: old\r\n\r\nold message\r\n"}
    return old unless uidl_mode == :duplicate
    old.merge('uid-second' => "Subject: second\r\n\r\nsecond\r\n")
  end
end

class TestPOPResumable < Test::Unit::TestCase
  OLD_UID = 'uid-old'
  NEW_UID = 'uid-new'
  OLD_CONTENT = "Subject: old\r\n\r\nold message\r\n"
  NEW_CONTENT = "Subject: new\r\n\r\nnew message\r\n"

  def test_recovers_after_retr_interruption_with_renumbered_messages
    server = FakePOP3Server.new(faults: [[1, :retr]])
    checkpoint = ResumableCheckpoint.new(contents: {})
    session = build_session(server, checkpoint)
    received = +''

    error = assert_raise(EOFError) do
      session.download(max_rounds: 1) do |message|
        message.download { |chunk| received << chunk }
      end
    end
    assert(error.is_a?(Net::POPError) || error.is_a?(EOFError) || error.is_a?(IOError))
    assert_equal [], checkpoint.downloaded_uids

    server.add_mail_at_front(NEW_UID, NEW_CONTENT)
    result = session.download(max_rounds: 2) do |message|
      received_by_uid = +''
      message.download do |chunk|
        received_by_uid << chunk
      end
      checkpoint.contents[message.unique_id] = received_by_uid
      checkpoint.confirm(message.unique_id)
    end

    assert_equal [NEW_UID, OLD_UID], result.messages.map(&:unique_id)
    assert_equal [[1, 'RETR 1'], [2, 'RETR 1'], [2, 'RETR 2']],
                 server.commands.select { |_, command| command.start_with?('RETR') }
    assert_equal [NEW_UID, OLD_UID], checkpoint.downloaded_uids
    assert_equal [NEW_UID, OLD_UID], checkpoint.confirmed_uids
    assert_equal OLD_CONTENT, checkpoint.contents[OLD_UID]
    assert_equal NEW_CONTENT, checkpoint.contents[NEW_UID]
    assert_equal result.messages, result.confirmed_messages
    assert_empty server.commands.map(&:last).grep(/\ADELE/)
  ensure
    server&.shutdown
  end

  def test_download_does_not_confirm_business_write
    server = FakePOP3Server.new
    checkpoint = ResumableCheckpoint.new
    session = build_session(server, checkpoint)

    result = session.download do |message|
      message.download do |chunk|
        checkpoint.contents[message.unique_id] = chunk.to_s
      end
    end

    assert_equal [OLD_UID], checkpoint.downloaded_uids
    assert_empty checkpoint.confirmed_uids
    assert_empty result.confirmed_messages
    assert_equal 1, result.downloaded_messages.length
  ensure
    server&.shutdown
  end

  def test_dele_success_is_not_committed_until_quit
    server = FakePOP3Server.new(faults: [[1, :dele]])
    checkpoint = ResumableCheckpoint.new(confirmed: [OLD_UID])
    session = build_session(server, checkpoint)

    assert_raise(Net::POPError, EOFError, IOError) do
      session.commit_confirmed(max_rounds: 1)
    end
    assert_empty checkpoint.deleted_uids
    assert_equal [OLD_UID], checkpoint.deletion_pending_uids
    assert_equal [OLD_UID], server.committed_uids

    server.add_mail_at_front(NEW_UID, NEW_CONTENT)
    response = session.commit_confirmed(max_rounds: 2)

    assert_match(/\A\+OK/, response)
    assert_equal [OLD_UID], checkpoint.deleted_uids
    assert_empty checkpoint.deletion_pending_uids
    assert_equal [NEW_UID], server.committed_uids
    assert_equal [[1, 'DELE 1'], [2, 'DELE 2']], server.commands.select { |_, command| command.start_with?('DELE') }
  ensure
    server&.shutdown
  end

  def test_quit_interruption_rolls_back_local_deletion_state
    server = FakePOP3Server.new(faults: [[1, :quit]])
    checkpoint = ResumableCheckpoint.new(confirmed: [OLD_UID])
    session = build_session(server, checkpoint)

    error = assert_raise(EOFError) do
      round = session.start_round
      round.commit_confirmed
    end
    assert(error.is_a?(Net::POPError) || error.is_a?(EOFError) || error.is_a?(IOError))
    assert_empty checkpoint.deleted_uids
    assert_equal [OLD_UID], checkpoint.deletion_pending_uids
    assert_empty server.committed_uids

    server.add_mail_at_front(NEW_UID, NEW_CONTENT)
    recovered_round = session.start_round
    assert_equal [NEW_UID], server.committed_uids
    assert_equal [OLD_UID], checkpoint.deleted_uids
    assert_empty checkpoint.deletion_pending_uids
    recovered_round.close
  ensure
    server&.shutdown
  end

  def test_rset_withdraws_deletion_state_without_deleting
    server = FakePOP3Server.new
    checkpoint = ResumableCheckpoint.new(confirmed: [OLD_UID])
    session = build_session(server, checkpoint)

    round = session.start_round
    assert_nil round.request_confirmed_deletions
    assert_equal [OLD_UID], checkpoint.deletion_pending_uids

    assert_nil round.reset_deletions
    assert_nil round.close
  ensure
    round&.abort
    assert_empty checkpoint.deletion_pending_uids
    assert_empty checkpoint.deleted_uids
    assert_equal [OLD_UID], server.committed_uids
    server&.shutdown
  end

  def test_reconcile_reports_unavailable_duplicate_and_missing_uidl
    unavailable = FakePOP3Server.new(uidl_mode: :error)
    checkpoint = ResumableCheckpoint.new
    assert_raise(Net::POPUIDLUnavailable) do
      build_session(unavailable, checkpoint).start_round
    end
  ensure
    unavailable&.shutdown
  end

  def test_reconcile_reports_duplicate_uidl
    server = FakePOP3Server.new(uidl_mode: :duplicate)
    checkpoint = ResumableCheckpoint.new
    error = assert_raise(Net::POPDuplicateUIDLError) do
      build_session(server, checkpoint).start_round
    end
    assert_equal ['dup'], error.result.duplicates
  ensure
    server&.shutdown
  end

  def test_reconcile_reports_confirmed_message_disappearance
    server = FakePOP3Server.new
    checkpoint = ResumableCheckpoint.new(confirmed: ['uid-elsewhere'])
    error = assert_raise(Net::POPMissingMailError) do
      build_session(server, checkpoint).start_round
    end
    assert_equal ['uid-elsewhere'], error.result.missing_confirmed
  ensure
    server&.shutdown
  end

  private

  def build_session(server, checkpoint)
    Net::POP3ResumableSession.new(checkpoint, max_rounds: 2) do
      server.connect
    end
  end

end
