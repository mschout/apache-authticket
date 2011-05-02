package Apache::AuthTicket::Base;

# ABSTRACT: Common methods for all Apache::AuthTicket versions.

use strict;
use base qw(Class::Accessor::Fast);
use DBI;
use SQL::Abstract;
use MRO::Compat;
use Digest::MD5;
use ModPerl::VersionUtil;

use constant DEBUGGING => 0;

__PACKAGE__->mk_accessors(qw(request _dbh _sql));

# configuration items
# PerlSetVar FooTicketDB  dbi:Pg:dbname=template1
# PerlSetVar FooDBUser     test
# PerlSetVar FooDBPassword  test
# PerlSetVar FooTicketTable tickets:ticket_hash
# PerlSetVar FooUserTable   users:usrname:passwd
# PerlSetVar FooPasswordStyle cleartext
# PerlSetVar FooSecretTable   ticketsecrets:sec_data:sec_version

our %DEFAULTS = (
    TicketExpires         => 15,
    TicketIdleTimeout     => 0,
    TicketLogoutURI       => '/',
    TicketDB              => 'dbi:Pg:dbname=template1',
    TicketDBUser          => 'test',
    TicketDBPassword      => 'test',
    TicketTable           => 'tickets:ticket_hash',
    TicketUserTable       => 'users:usrname:passwd',
    TicketPasswordStyle   => 'cleartext',
    TicketSecretTable     => 'ticketsecrets:sec_data:sec_version',
    TicketLoginHandler    => '/login',
    TicketCheckIP         => 1,
    TicketCheckBrowser    => 0
);

# configured items get dumped in here
our %CONFIG = ();

sub configure {
    my ($class, $auth_name, $conf) = @_;

    $class->push_handler(PerlChildInitHandler => sub {
        for (keys %$conf) {
            die "bad configuration parameter $_" unless defined $DEFAULTS{$_};
            $CONFIG{$auth_name}->{$_} = $conf->{$_};
        }
    });
}

# check credentials and return a session key if valid
# return undef if invalid
sub authen_cred {
    my ($class, $r, @cred) = @_;

    my $self = $class->new($r);

    my ($user, $pass) = @cred;
    my ($result, $msg) = $self->check_credentials($user, $pass);
    if ($result) {
        return $self->make_ticket($r, $user);
    }
    else {
        return undef;
    }
}

# check a session key, return user id
# return undef if its not valid.
sub authen_ses_key {
    my ($class, $r, $session_key) = @_;

    my $self = $class->new($r);

    if ($self->verify_ticket($session_key)) {
        my %ticket = $self->_unpack_ticket($session_key);
        return $ticket{user};
    }
    else {
        return undef;
    }
}

sub sql {
    my $self = shift;

    unless (defined $self->_sql) {
        $self->_sql( SQL::Abstract->new );
    }

    $self->_sql;
}

sub _get_config_item {
    my ($class, $r, $item) = @_;

    my $auth_name = $r->auth_name;

    my $value = $class->str_config_value(
        $r->dir_config("${auth_name}$item"),
        $CONFIG{$auth_name}->{$item},
        $DEFAULTS{$item});

    warn "returning [$value] for $item" if DEBUGGING;
    return $value;
}

sub login_screen ($$) {
    my ($class, $r) = @_;

    my $auth_name = $r->auth_name;

    my $action = $class->_get_config_item($r, 'TicketLoginHandler');

    my $destination = $r->prev->uri;
    my $args = $r->prev->args;
    if ($args) {
        $destination .= "?$args";
    }

    $class->make_login_screen($r, $action, $destination);

    return $class->apache_const('OK');
}

sub make_login_screen {
    my ($self, $r, $action, $destination) = @_;

    if (DEBUGGING) {
        # log what we think is wrong.
        my $reason = $r->prev->subprocess_env("AuthCookieReason");
        $r->log_error("REASON FOR AUTH NEEDED: $reason");
        $reason = $r->prev->subprocess_env("AuthTicketReason");
        $r->log_error("AUTHTICKET REASON: $reason");
    }


    $r->content_type('text/html');

    $r->send_http_header if ModPerl::VersionUtil->is_mp1;

    $r->print(
        q{<!DOCTYPE HTML PUBLIC  "-//W3C//DTD HTML 3.2//EN">},
        q{<HTML>},
        q{<HEAD>},
        q{<TITLE>Log in</TITLE>},
        q{</HEAD>},
        q{<BODY bgcolor="#ffffff">},
        q{<H1>Please Log In</H1>}
    );

    $r->print(
        qq{<form method="post" action="$action">},
        qq{<input type="hidden" name="destination" value="$destination">},
        q{<table>},
        q{<tr>},
        q{<td>Name</td>},
        q{<td><input type="text" name="credential_0"></td>},
        q{</tr>},
        q{<tr>},
        q{<td>Password</td>},
        q{<td><input type="password" name="credential_1"></td>},
        q{</tr>},
        q{</table>},
        q{<input type="submit" value="Log In">},
        q{<p>},
        q{</form>},
        q{<EM>Note: </EM>},
        q{Set your browser to accept cookies in order for login to succeed.},
        q{You will be asked to log in again after some period of time.},
        q{</body></html>}
    );

    return $self->apache_const('OK');
}

sub logout ($$) {
    my ($class, $r) = @_;

    my $self = $class->new($r);

    $self->delete_ticket($r);
    $self->next::method($r); # AuthCookie logout

    $r->err_headers_out->add('Location' => $self->{TicketLogoutURI});

    return $class->apache_const('REDIRECT');
}

##################### END STATIC METHODS ###########################3
sub new {
    my ($class, $r) = @_;

    return $class->SUPER::new({request => $r});
}

sub dbh {
    my $self = shift;

    unless (defined $self->_dbh) {
        $self->_dbh($self->dbi_connect);
    }

    $self->_dbh;
}

sub dbi_connect {
    my $self = shift;

    my $r         = $self->request;
    my $auth_name = $r->auth_name;

    my ($db, $user, $pass) = map {
        $self->_get_config_item($r, $_)
    } qw/TicketDB TicketDBUser TicketDBPassword/;

    my $dbh = DBI->connect_cached($db, $user, $pass)
        or die "DBI Connect failure: ", DBI->errstr, "\n";

    return $dbh;
}

# boolean check_user(String username)
#
# return true if a username exists.
sub check_user {
    my ($self, $user) = @_;

    my $dbh = $self->dbh;

    my $rows = 0;

    my ($table, $user_field) = split(/:/, $self->{TicketUserTable});

    my ($stmt, @bind) =
        $self->sql->select($table, 'COUNT(*)', {$user_field => $user});

    eval {
        ($rows) = $dbh->selectrow_array($stmt, undef, @bind);
    };
    if ($@) {
        $dbh->rollback; 
        die $@;
    }

    return $rows;
}

# String get_passwd(String username)
#
# return the password associated with a user
sub get_password {
    my ($self, $user) = @_;

    my $dbh = $self->dbh;

    my ($table, $user_field, $passwd_field) = 
        split(/:/, $self->{TicketUserTable});

    my ($stmt, @bind) =
        $self->sql->select($table, [$passwd_field], {$user_field => $user});

    my $passwd = undef;
    eval {
        ($passwd) = $dbh->selectrow_array($stmt, undef, @bind);
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return $passwd;
}

sub check_credentials {
    my ($self, $user, $password) = @_;

    my ($table, $user_field, $pass_field) = 
        split(/:/, $self->{TicketUserTable});

    my $dbh = $self->dbh;

    return (undef, "Can't open database: $DBI::errstr") unless $dbh;

    return (undef, "invalid account") unless $self->check_user($user);

    # we might add an option for crypt or MD5 style password someday
    my $saved_passwd = $self->get_password($user);

    my $style = $self->{TicketPasswordStyle};

    unless ($self->compare_password($style, $password, $saved_passwd)) {
        return (undef, 'password mismatch')
    }

    # its valid.
    return (1, '');
}

#
# ($secret, $version) = $obj->fetch_secret();
# ($secret, $version) = $obj->fetch_secret($ver);
#
sub fetch_secret {
    my ($self, $version) = @_;

    my $dbh = $self->dbh;

    my ($secret_table, $secret_field, $secret_version_field) =
        split(/:/, $self->{TicketSecretTable});

    unless (defined $version) {
        $version = $self->_get_max_secret_version;
    }

    # generate SQL
    my @fields = ($secret_field, $secret_version_field);
    my %where = ( $secret_version_field => $version );
    my ($stmt, @bind) = $self->sql->select($secret_table, \@fields, \%where);

    my ($secret, $ret_version) = (undef, undef);
    eval {
        ($secret, $ret_version) = $dbh->selectrow_array($stmt, undef, @bind);
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return ($secret, $ret_version);
}

#
# create a new ticket, save the hash, and return an Apache::Cookie object
# also, put the cookie in the outgoing headers so it wil be set on the client
#
sub make_ticket {
    my ($self, $r, $user_name) = @_;

    my $now     = time;
    my $expires = $now + $self->{TicketExpires} * 60;
    my ($secret, $sec_version) = $self->fetch_secret();

    my @fields = ($secret, $sec_version, $now, $expires, $user_name);

    # only add ip if TicketCheckIP is on.
    if ($self->_get_config_item($r, 'TicketCheckIP')) {
        push @fields, $r->connection->remote_ip;
    }

    if ($self->_get_config_item($r, 'TicketCheckBrowser')) {
        push @fields, $self->user_agent;
    }

    my $hash = $self->hash_for(@fields);

    my %key = (
        'version' => $sec_version,
        'time'    => $now,
        'user'    => $user_name,
        'expires' => $expires,
        'hash'    => $hash
    );

    eval {
        $self->save_hash($key{'hash'});
    };
    if ($@) {
        warn "save_hash() failed, treating this request as invalid login.\n";
        warn "reason: $@";
        return;
    }

    return $self->_pack_ticket(%key);
}

# invalidate the ticket by expiring the cookie, and delete the hash locally
sub delete_ticket {
    my ($self, $r) = @_;

    my $key = $self->key($r);
    warn "delete_ticket: key $key" if DEBUGGING;

    my %ticket = $self->_unpack_ticket($key);

    $self->delete_hash($ticket{'hash'});
}

#
# boolean check_ticket_format(%ticket)
#
# return true if the ticket contains the required fields.
#
sub check_ticket_format {
    my ($self, %key) = @_;

    $self->request->log_error("key is ".join(' ', %key)) if DEBUGGING;
    for my $param (qw(version time user expires hash)) {
        return 0 unless defined $key{$param};
    }

    return 1;
}

sub _unpack_ticket {
    my ($self, $key) = @_;

    return unless defined $key;

    my @attrs = split ':', $key;

    # odd number of attrs is not a valid key
    return unless @attrs % 2 == 0;

    return @attrs;
}

sub _pack_ticket {
    my ($self, %ticket) = @_;
    return join(':', %ticket);
}

#
# boolean verify_ticket($key)
#
# Verify the ticket and return true or false.
#
sub verify_ticket {
    my ($self, $key) = @_;

    my $r = $self->request;

    warn "ticket is $key\n" if DEBUGGING;
    my ($secret, $sec_version);
    my %ticket = $self->_unpack_ticket($key);

    unless ($self->check_ticket_format(%ticket)) {
        $r->subprocess_env(AuthTicketReason => 'malformed_ticket');
        return 0;
    }
    unless ($self->is_hash_valid($ticket{'hash'})) {
        $r->subprocess_env(AuthTicketReason => 'invalid_hash');
        return 0;
    }
    unless ($r->request_time < $ticket{'expires'}) {
        $r->subprocess_env(AuthTicketReason => 'expired_ticket');
        return 0;
    }
    unless (($secret, $sec_version) = $self->fetch_secret($ticket{'version'})) {
        # can't get server secret
        $r->subprocess_env(AuthTicketReason => 'missing_secret');
        return 0;
    }
    if ($self->_ticket_idle_timeout($ticket{'hash'})) {
        # user has exceeded idle-timeout
        $r->subprocess_env(AuthTicketReason => 'idle_timeout');
        $self->delete_hash($ticket{'hash'});
        return 0;
    }

    # create a new hash and verify that it matches the supplied hash
    # (prevents tampering with the cookie)

    my @fields = ($secret, @ticket{qw(version time expires user)});

    if ($self->_get_config_item($r, 'TicketCheckIP')) {
        my $ip = $r->connection->remote_ip;
        push @fields, $ip;
    }

    if ($self->_get_config_item($r, 'TicketCheckBrowser')) {
        push @fields, $self->user_agent;
    }

    warn "FIELDS: [@fields]\n" if DEBUGGING;

    my $newhash = $self->hash_for(@fields);

    unless ($newhash eq $ticket{'hash'}) {
        # ticket hash does not match (ticket tampered with?)
        $r->subprocess_env(AuthTicketReason => 'tampered_hash');
        return 0;
    }

    # otherwise, everything is ok
    $self->_update_ticket_timestamp($ticket{'hash'});

    $self->set_user($ticket{user});

    return 1;
}

########## SERVER SIDE HASH MANAGEMENT METHODS

sub _update_ticket_timestamp {
    my ($self, $hash) = @_;

    my $time = $self->request->request_time;
    my $dbh = $self->dbh;

    my ($table, $tick_field, $ts_field) = split(':', $self->{TicketTable});

    my ($query, @bind) = $self->sql->update($table,
        {$ts_field   => $time},
        {$tick_field => $hash});

    eval {
        my $sth = $dbh->do($query, undef, @bind);
        $dbh->commit unless $dbh->{AutoCommit};
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }
}

# boolean _ticket_idle_timeout(String hash)
#
# return true if the ticket table timestamp is older than the IdleTimeout
# value.
sub _ticket_idle_timeout {
    my ($self, $hash) = @_;

    my $idle = $self->{TicketIdleTimeout} * 60;
    return 0 unless $idle;       # if not timeout set, its still valid.

    my $db_time = $self->{DBTicketTimeStamp};
    my $time = $self->request->request_time;
    if (DEBUGGING) {
        warn "Last activity: ", ($time - $db_time), " secs ago\n";
        warn "Fail if thats > ", ($idle), "\n";
    }

    if ( ($time - $db_time)  > $idle ) {
        # its timed out
        return 1;
    }
    else {
        return 0;
    }
}

#
# save the ticket hash in the db
#
sub save_hash {
    my ($self, $hash) = @_;

    my ($table, $tick_field, $ts_field) = split(/:/, $self->{TicketTable});

    my ($query, @bind) = $self->sql->insert($table, {
        $tick_field => $hash,
        $ts_field   => $self->request->request_time });

    my $dbh = $self->dbh;

    eval {
        my $sth = $dbh->do($query, undef, @bind);
        $dbh->commit unless $dbh->{AutoCommit};
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }
}

#
# delete the ticket hash from the db
#
sub delete_hash {
    my ($self, $hash) = @_;

    my ($table, $tick_field) = split(/:/, $self->{TicketTable});

    my ($query, @bind) = $self->sql->delete($table, { $tick_field => $hash });

    my $dbh = $self->dbh;

    eval {
        my $sth = $dbh->do($query, undef, @bind);
        $dbh->commit unless $dbh->{AutoCommit} || 0;
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }
}

#
# return TRUE if the hash is in the db
#
sub is_hash_valid {
    my ($self, $hash) = @_;

    my ($table, $tick_field, $ts_field) = split(/:/, $self->{TicketTable});

    my ($query, @bind) = $self->sql->select($table, [$tick_field, $ts_field], 
        { $tick_field => $hash });

    my $dbh = $self->dbh;

    my ($db_hash, $ts) = (undef, undef);
    eval {
        ($db_hash, $ts) = $dbh->selectrow_array($query, undef, @bind);
        $self->{DBTicketTimeStamp} = $ts;   # cache for later use.
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return (defined $db_hash and $db_hash eq $hash) ? 1 : 0;
}

sub _get_max_secret_version {
    my ($self) = @_;

    my ($secret_table, $secret_field, $secret_version_field) =
        split(/:/, $self->{TicketSecretTable});

    my ($query) = $self->sql->select($secret_table, ["MAX($secret_version_field)"]);

    my $dbh = $self->dbh;

    my $version = undef;
    eval {
        ($version) = $dbh->selectrow_array($query);
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return $version;
}

# compute a hash for the given values.
sub hash_for {
    my $self = shift;

    return Digest::MD5::md5_hex(@_);
}

# get clients user agent string
sub user_agent {
    my $self = shift;

    return $ENV{HTTP_USER_AGENT}
        || $self->request->headers_in->get('User-Agent')
        || '';
}

sub compare_password {
    my ($self, $style, $check, $expected) = @_;

    if ($style eq 'crypt') {
        return crypt($check, $expected) eq $expected;
    }
    elsif ($style eq 'cleartext') {
        return $check eq $expected;
    }
    elsif ($style eq 'md5') {
        return Digest::MD5::md5_hex($check) eq $expected;
    }
    else {
        die "unrecognized password style '$style'";
    }

    return 0;
}

# convert recognized true/false aliases to boolean. Multiple strings may be passed and the
# first defined one will be converted.  If none of the strings are defined,
# undef is returned.
sub str_config_value {
    my $self = shift;

    for my $value (@_) {
        next unless defined $value;

        my $test = lc $value;

        # convert booleans to 1/0
        if ($test =~ /^(?:1|on|yes|true)$/) {
            return 1;
        }
        elsif ($test =~ /^(?:0|off|no|false)$/) {
            return 0;
        }
        else {
            # return value unchanged.
            return $value;
        }
    }

    return;
}

# subclass must provide
sub push_handler { die "unimplemented" }

# subclass must provide
sub set_user { die "unimplemented" }

# subclass must provide
sub apache_const { die "unimplemented" }

1;

__END__

=head1 SYNOPSIS

 # This module is internal to Apache::AuthTicket.  you should never use this
 # module directly.

=head1 DESCRIPTION

This module is a base class providing common methods for C<Apache::AuthTicket>
and C<Apache2::AuthTicket>.

