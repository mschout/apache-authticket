#
# $Id: AuthTicket.pm 40 2005-04-18 19:48:25Z mschout $
#

package Apache2::AuthTicket;

use strict;
use base 'Apache2::AuthCookie';
use vars qw(%DEFAULTS %CONFIG);

use Apache2::Const qw(REDIRECT OK);
use Apache2::RequestIO;
use Apache2::Connection;
use Apache2::ServerUtil;
use DBI ();
use SQL::Abstract;
use Digest::MD5 qw(md5_hex);

use constant DEBUGGING => 0;

our $VERSION = '0.90_01';

# configuration items
# PerlSetVar FooTicketDB  dbi:Pg:dbname=template1
# PerlSetVar FooDBUser     test
# PerlSetVar FooDBPassword  test
# PerlSetVar FooTicketTable tickets:ticket_hash
# PerlSetVar FooUserTable   users:usrname:passwd
# PerlSetVar FooPasswordStyle cleartext
# PerlSetVar FooSecretTable   ticketsecrets:sec_data:sec_version

%DEFAULTS = (
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
    TicketLoginHandler    => '/login'
);

# configured items get dumped in here
%CONFIG = ();

sub configure {
    my ($class, $auth_name, $conf) = @_;

    # XXX untested.
    my $s = Apache2::ServerUtil->server;

    $s->push_handlers( PerlChildInitHandler =>
        sub {
            for (keys %$conf) {
                die "bad configuration parameter $_" 
                    unless defined $DEFAULTS{$_};
                $CONFIG{$auth_name}->{$_} = $conf->{$_};
            }
            #warn 'After config. %CONFIGURE looks like this\n',
            #     Dumper(\%CONFIG);
        }
    );
}

# check credentials and return a session key if valid
# return undef if invalid
sub authen_cred {
    my ($class, $r, @cred) = @_;

    my $this = $class->new($r);

    my ($user, $pass) = @cred;
    my ($result, $msg) = $this->check_credentials($user, $pass);
    if ($result) {
        return $this->make_ticket($r, $user);
    }
    else {
        return undef;
    }
}

# check a session key, return user id
# return undef if its not valid.
sub authen_ses_key {
    my ($class, $r, $session_key) = @_;

    my $this = $class->new($r);
    if ($this->verify_ticket($session_key)) {
        my %ticket = $this->_unpack_ticket($session_key);
        return $ticket{user};
    } else {
        return undef;
    }
}

sub sql {
    my $self = shift;

    unless (defined $self->{sql}) {
        $self->{sql} = new SQL::Abstract;
    }

    return $self->{sql};
}

sub _get_config_item {
    my ($class, $r, $item) = @_;

    my $auth_name = $r->auth_name;

    my $value = $r->dir_config("${auth_name}$item") ||
           $CONFIG{$auth_name}->{$item} ||
           $DEFAULTS{$item};
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

    return OK;
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

    $r->print(
        q{<!DOCTYPE HTML PUBLIC  "-//W3C//DTD HTML 3.2//EN">},
        q{<HTML>},
        q{<HEAD>},
        q{<TITLE>Log in</TITLE>},
        q{</HEAD>},
        q{<BODY bgcolor="#ffffff">},
        q{<H1>Please Log In</H1>}
    );

    #if (defined $msg and $msg) {
    #    $r->print(qq{<h2><font color="#ff0000">Error: $msg</font></h2>});
    #}

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

    return OK;
}

sub logout ($$) {
    my ($class, $r) = @_;

    if (lc $r->dir_config('Filter') eq 'on') {
        $r->filter_register;
    }

    my $this = $class->new($r);

    $this->delete_ticket($r);
    $this->SUPER::logout($r);

    $r->err_headers_out->add('Location' => $this->{TicketLogoutURI});
    return REDIRECT;
}

##################### END STATIC METHODS ###########################3
sub new {
    my ($class, $r) = @_;
    $class = ref $class || $class;

    my $this = bless {
        _REQUEST => $r
    }, $class;

    $this->init($r);

    #warn "After init I look like this\n";
    #warn Dumper($this), "\n";

    return $this;
}

sub init {
    my ($this, $r) = @_;
    $this->{_DBH} = $this->dbi_connect;

    my $auth_name = $r->auth_name;

    # initialize configuration
    map {
        $this->{$_} = $this->_get_config_item($r, $_);
    } keys %DEFAULTS;
}

sub request { shift->{_REQUEST} }
sub dbh     { shift->{_DBH} }

sub dbi_connect {
    my ($this) = @_;
    $this->_log_entry if DEBUGGING;

    my $r         = $this->request;
    my $auth_name = $r->auth_name;

    my ($db, $user, $pass) = map {
        $this->_get_config_item($r, $_)
    } qw/TicketDB TicketDBUser TicketDBPassword/;

    my $dbh = DBI->connect_cached($db, $user, $pass)
        or die "DBI Connect failure: ", DBI->errstr, "\n";

    return $dbh;
}

# boolean check_user(String username)
#
# return true if a username exists.
sub check_user {
    my ($this, $user) = @_;
    $this->_log_entry if DEBUGGING;

    my $dbh = $this->dbh;

    my $rows = 0;

    my ($table, $user_field) = split(/:/, $this->{TicketUserTable});

    my ($stmt, @bind) =
        $this->sql->select($table, 'COUNT(*)', {$user_field => $user});

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
    my ($this, $user) = @_;
    $this->_log_entry if DEBUGGING;

    my $dbh = $this->dbh;

    my ($table, $user_field, $passwd_field) = 
        split(/:/, $this->{TicketUserTable});

    my ($stmt, @bind) =
        $this->sql->select($table, [$passwd_field], {$user_field => $user});

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
    my ($this, $user, $password) = @_;
    $this->_log_entry if DEBUGGING;

    my ($table, $user_field, $pass_field) = 
        split(/:/, $this->{TicketUserTable});

    my $dbh = $this->dbh;

    return (undef, "Can't open database: $DBI::errstr") unless $dbh;

    return (undef, "invalid account") unless $this->check_user($user);

    # we might add an option for crypt or MD5 style password someday
    my $saved_passwd = $this->get_password($user);

    my $result = 0;

    my $style = $this->{TicketPasswordStyle};
    if ($style eq 'cleartext') {
        $result = $this->_compare_password_cleartext($password, $saved_passwd);
    }
    elsif ($style eq 'crypt') {
        $result = $this->_compare_password_crypt($password, $saved_passwd);
    }
    elsif ($style eq 'md5') {
        $result = $this->_compare_password_md5($password, $saved_passwd);
    }
    else {
        die "unknown TicketPasswordStyle: $style\n";
    }

    return (undef, "password mismatch") unless $result;

    # its valid.
    return (1, '');
}

#
# ($secret, $version) = $obj->fetch_secret();
# ($secret, $version) = $obj->fetch_secret($ver);
#
sub fetch_secret {
    my ($this, $version) = @_;
    $this->_log_entry if DEBUGGING;

    my $dbh = $this->dbh;

    my ($secret_table, $secret_field, $secret_version_field) =
        split(/:/, $this->{TicketSecretTable});

    unless (defined $version) {
        $version = $this->_get_max_secret_version;
    }

    # generate SQL
    my @fields = ($secret_field, $secret_version_field);
    my %where = ( $secret_version_field => $version );
    my ($stmt, @bind) = $this->sql->select($secret_table, \@fields, \%where);

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
    my ($this, $r, $user_name) = @_;
    $this->_log_entry if DEBUGGING;

    my $now      = time();
    my $expires  = $now + $this->{TicketExpires} * 60;
    my $ip       = $r->connection->remote_ip;
    my ($secret, $sec_version) = $this->fetch_secret();

    my $hash = md5_hex($secret .
                   md5_hex(join ':', $secret, $ip, $sec_version, 
                                      $now, $expires, $user_name)
               );

    my %key = (
        'version' => $sec_version,
        'time'    => $now,
        'user'    => $user_name,
        'expires' => $expires,
        'hash'    => $hash
    );

    eval {
        $this->save_hash($key{'hash'});
    };
    if ($@) {
        warn "save_hash() failed, treating this request as invalid login.\n";
        warn "reason: $@";
        return;
    }

    return $this->_pack_ticket(%key);
}

# invalidate the ticket by expiring the cookie, and delete the hash locally
sub delete_ticket {
    my ($this, $r) = @_;
    $this->_log_entry if DEBUGGING;

    my $key = $this->key($r);
    warn "delete_ticket: key $key" if DEBUGGING;

    my %ticket = $this->_unpack_ticket($key);

    $this->delete_hash($ticket{'hash'});
}

#
# boolean check_ticket_format(%ticket)
#
# return true if the ticket contains the required fields.
#
sub check_ticket_format {
    my ($this, %key) = @_;
    $this->_log_entry if DEBUGGING;

    $this->request->log_error("key is ".join(' ', %key)) if DEBUGGING;
    for my $param (qw(version time user expires hash)) {
        return 0 unless defined $key{$param};
    }

    return 1;
}

sub _unpack_ticket {
    my ($self, $key) = @_;
    return split(':', $key);
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
    my ($this, $key) = @_;
    $this->_log_entry if DEBUGGING;

    my $r = $this->request;

    warn "ticket is $key\n" if DEBUGGING;
    my ($secret, $sec_version);
    my %ticket = $this->_unpack_ticket($key);

    unless ($this->check_ticket_format(%ticket)) {
        $r->subprocess_env(AuthTicketReason => 'malformed_ticket');
        return 0;
    }
    unless ($this->is_hash_valid($ticket{'hash'})) {
        $r->subprocess_env(AuthTicketReason => 'invalid_hash');
        return 0;
    }
    unless ($r->request_time < $ticket{'expires'}) {
        $r->subprocess_env(AuthTicketReason => 'expired_ticket');
        return 0;
    }
    unless (($secret, $sec_version) = $this->fetch_secret($ticket{'version'})) {
        # cat get server secret
        $r->subprocess_env(AuthTicketReason => 'missing_secret');
        return 0;
    }
    if ($this->_ticket_idle_timeout($ticket{'hash'})) {
        # user has exceeded idle-timeout
        $r->subprocess_env(AuthTicketReason => 'idle_timeout');
        $this->delete_hash($ticket{'hash'});
        return 0;
    }

    # create a new hash and verify that it matches the supplied hash
    # (prevents tampering with the cookie)
    my $ip = $r->connection->remote_ip;
    my $newhash = md5_hex($secret .
                      md5_hex(join ':', $secret, $ip,
                          @ticket{qw(version time expires user)})
                  );

    unless ($newhash eq $ticket{'hash'}) {
        # ticket hash does not match (ticket tampered with?)
        $r->subprocess_env(AuthTicketReason => 'tampered_hash');
        return 0;
    }

    # otherwise, everything is ok
    $this->_update_ticket_timestamp($ticket{'hash'});
    $r->user($ticket{'user'});
    return 1;
}

########## SERVER SIDE HASH MANAGEMENT METHODS

sub _update_ticket_timestamp {
    my ($this, $hash) = @_;

    my $time = $this->request->request_time;
    my $dbh = $this->dbh;

    my ($table, $tick_field, $ts_field) = split(':', $this->{TicketTable});

    my $query = qq{
        UPDATE $table
        SET    $ts_field = ?
        WHERE  $tick_field = ?
    };

    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($time, $hash);
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
    my ($this, $hash) = @_;

    my $idle = $this->{TicketIdleTimeout} * 60;
    return 0 unless $idle;       # if not timeout set, its still valid.

    my $db_time = $this->{DBTicketTimeStamp};
    my $time = $this->request->request_time;
    if (DEBUGGING) {
        warn "Last activity: ", ($time - $db_time), " secs ago\n";
        warn "Fail if thats > ", ($idle), "\n";
    }

    if ( ($time - $db_time)  > $idle ) {
        # its timed out
        return 1;
    } else {
        return 0;
    }
}

#
# save the ticket hash in the db
#
sub save_hash {
    my ($this, $hash) = @_;
    $this->_log_entry if DEBUGGING;

    my ($table, $tick_field, $ts_field) = split(/:/, $this->{TicketTable});
    my $dbh = $this->dbh;

    my $query = qq{
        INSERT INTO $table ($tick_field, $ts_field)
        VALUES (?, ?)
    };

    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($hash, $this->request->request_time);
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
    my ($this, $hash) = @_;
    $this->_log_entry if DEBUGGING;

    my ($table, $tick_field) = split(/:/, $this->{TicketTable});
    my $dbh = $this->dbh;

    my $query = qq{
        DELETE
        FROM    $table
        WHERE   $tick_field = ?
    };

    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($hash);
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
    my ($this, $hash) = @_;
    $this->_log_entry if DEBUGGING;

    my ($table, $tick_field, $ts_field) = split(/:/, $this->{TicketTable});
    my $dbh = $this->dbh;

    my $query = qq{
        SELECT  $tick_field, $ts_field
        FROM    $table
        WHERE   $tick_field = ?
    };

    my ($db_hash, $ts) = (undef, undef);
    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($hash);
        ($db_hash, $ts) = $sth->fetchrow_array;
        $this->{DBTicketTimeStamp} = $ts;   # cache for later use.
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return (defined $db_hash and $db_hash eq $hash) ? 1 : 0;
}

# PRIVATE METHODS ############################################################

# logs entry into methods
sub _log_entry {
    my ($this) = @_;
    my ($package, $filename, $line, $subroutine) = caller(1);
    $this->request->log_error("ENTRY $subroutine [line $line]");
}

# compare cleartext style passwords
sub _compare_password_cleartext {
    my ($this, $clearpass, $saved_pass) = @_;
    $this->_log_entry if DEBUGGING;

    return $clearpass eq $saved_pass;
}

# compare crypt() style passwords
sub _compare_password_crypt {
    my ($this, $clearpass, $saved_pass) = @_;
    $this->_log_entry if DEBUGGING;

    my $test_pass = crypt($clearpass, $saved_pass);
    return $test_pass eq $saved_pass;
}

# compare md5 style passwords
sub _compare_password_md5 {
    my ($this, $clearpass, $saved_pass) = @_;
    $this->_log_entry if DEBUGGING;

    my $test_pass = md5_hex($clearpass);
    return $test_pass eq $saved_pass;
}

sub _get_max_secret_version {
    my ($this) = @_;

    my ($secret_table, $secret_field, $secret_version_field) =
        split(/:/, $this->{TicketSecretTable});

    my $dbh = $this->dbh;

    my $query = qq{
        SELECT MAX($secret_version_field)
        FROM   $secret_table
    };

    my $version = undef;
    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute;
        $sth->bind_columns(\$version);
        $sth->fetch;
        $sth->finish;
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return $version;
}

1;

__END__

=head1 NAME

Apache2::AuthTicket - Cookie based access module.

=head1 SYNOPSIS

 # in httpd.conf
 PerlModule Apache2::AuthTicket
 PerlSetVar FooTicketDB DBI:mysql:database=mschout;host=testbed
 PerlSetVar FooTicketDBUser test
 PerlSetVar FooTicketDBPassword secret
 PerlSetVar FooTicketTable tickets:ticket_hash:ts
 PerlSetVar FooTicketUserTable myusers:usename:passwd
 PerlSetVar FooTicketPasswordStyle cleartext
 PerlSetVar FooTicketSecretTable ticket_secrets:sec_data:sec_version
 PerlSetVar FooTicketExpires 15
 PerlSetVar FooTicketLogoutURI /foo/index.html
 PerlSetVar FooTicketLoginHandler /foologin
 PerlSetVar FooTicketIdleTimeout 1
 PerlSetVar FooPath /
 PerlSetVar FooDomain .foo.com
 PerlSetVar FooSecure 1
 PerlSetVar FooLoginScript /foologinform
 
 <Location /foo>
     AuthType Apache2::AuthTicket
     AuthName Foo
     PerlAuthenHandler Apache2::AuthTicket->authenticate
     PerlAuthzHandler Apache2::AuthTicket->authorize
     require valid-user
 </Location>
 
 <Location /foologinform>
     AuthType Apache2::AuthTicket
     AuthName Foo
     SetHandler perl-script
     PerlResponseHandler Apache2::AuthTicket->login_screen
 </Location>
 
 <Location /foologin>
     AuthType Apache2::AuthTicket
     AuthName Foo
     SetHandler perl-script
     PerlResponseHandler Apache2::AuthTicket->login
 </Location>
 
 <Location /foo/logout>
     AuthType Apache2::AuthTicket
     AuthName Foo
     SetHandler perl-script
     PerlResponseHandler Apache2::AuthTicket->logout
 </Location>

=head1 DESCRIPTION

This module provides ticket based access control.  The theory behind this is
similar to the system described in the eagle book.

This module works using HTTP cookies to check if a user is authorized to view a
page.  I<Apache2::AuthCookie> is used as the underlying mechanism for managing
cookies.

This module was designed to be as extensible as possible.  Its quite likely
that you will want to create your own subclass of I<Apache2::AuthTicket> in
order to customize various aspects of this module (show your own versions of
the forms, override database methods etc). 

This system uses cookies to authenticate users.  When a user is authenticated
through this system, they are issued a cookie consisting of the time, the
username of the user, the expriation time of the cookie, a "secret" version
(described later), and a cryptographic signature.  The cryptographic signature
is generated using the MD5 algorithm on the cookie data and a "secret" key that
is read from a database.  Each secret key also has a version number associated
with it.  This allows the site administrator to issue a new secret periodically
without invalidating the current valid tickets.   For example, the site
administrator might periodically insert a new secret key into the databse
periodically, and flush secrets that are more than 2 days old.  Since the
ticket issued to the user contains the secret version, the authentication
process will still allow tickets to be authorized as long as the corresponding
secrets exist in the ticket secrets table. 

The actual contents and length of secret data is left to the site
administrator. A good choice might be to read data from /dev/random, unpack it
into a hex string and save that.

This system should be reasonably secure becuase the IP address of the end user
is incorporated into the cryptographic signature. If the ticket were
intercepted, then an attacker would have to steal the user's IP address in
order to be able to use the ticket.  Plus, since the tickets can expire
automatically, we can be sure that the ticket is not valid for a long period of
time.  Finally, by using the I<Secure> mode of I<Apache2::AuthCookie>, the
ticket is not passed over unencrypted connections.  In order to attack this
system, an attacker would have to exploit both the MD5 algorightm as well as
SSL. Chances are, by the time the user could break both of these, the ticket
would no longer be valid.

=head1 CONFIGURATION

There are two things you must do in order to configure this module: 

 1) configure your mod_perl apache server
 2) create the necessary database tables.

=head2 Apache Configuration - httpd.conf

There are two ways that this module could be configured.  Either by using a
function call in startup.pl, or by configuring each handler explicitly in
httpd.conf.  If you decide to mix and match using calls to Apache2::AuthTicket->configure() with directives in httpd.conf, then remember that the following precedence applies:

 o If a directive is specified in httpd.conf, it will be used.
 o else if a directive is specified by configure(), then the 
   configure() value will be used.
 o else a default value will be used.

Default values are subject to change in later versions, so you are better of
explicitly configuring all values and not relying on any defaults.

There are four blocks that need to be entered into httpd.conf.  The first of
these is the block specifying your access restrictions.  This block should look
somrthing like this:

 <Location /foo>
     AuthType Apache2::AuthTicket
     AuthName Foo
     PerlAuthenHandler Apache2::AuthTicket->authenticate
     PerlAuthzHandler Apache2::AuthTicket->authorize
     require valid-user
 </Location>

The remaining blocks control how to display the login form, and the login and
logout urls.  These blocks should look similar to this:

 <Location /foologinform>
     AuthType Apache2::AuthTicket
     AuthName Foo
     SetHandler perl-script
     PerlResponseHandler Apache2::AuthTicket->login_screen
 </Location>
 
 <Location /foologin>
     AuthType    Apache2::AuthTicket
     AuthName    Foo
     SetHandler  perl-script
     PerlResponseHandler Apache2::AuthTicket->login
 </Location>
 
 <Location /foo/logout>
     AuthType Apache2::AuthTicket
     AuthName Foo
     SetHandler perl-script
     PerlResponseHandler Apache2::AuthTicket->logout
 </Location>

=head2 Apache Configuration - startup.pl

Any I<Apache2::AuthTicket> configuration items can be set in startup.pl.  You
can configure an AuthName like this:

 Apache2::AuthTicket->configure(String auth_name, *Hash config)

Note that when configuring this way you dont prefix the configuration items
with the AuthName value like you do when using PerlSetVar directives.

Note: You must still include I<Apache2::AuthCookie> configuration directives in 
httpd.conf when configuring the server this way.  These items include:

    PerlSetVar FooPath /
    PerlSetVar FooDomain .foo.com
    PerlSetVar FooSecure 1
    PerlSetVar FooLoginScript /foologinform

example:
 Apache2::AuthTicket->configure('Foo', {
     TicketDB            => 'DBI:mysql:database=test;host=foo',
     TicketDBUser        => 'mschout',
     TicketDBPassword    => 'secret',
     TicketTable         => 'tickets:ticket_hash:ts',
     TicketUserTablei    => 'myusers:usename:passwd',
     TicketPasswordStyle => 'cleartext',
     TicketSecretTable   => 'ticket_secrets:sec_data:sec_version',
     TicketExpires       => '15',
     TicketLogoutURI     => '/foo/index.html',
     TicketLoginHandler  => '/foologin',
     TicketIdleTimeout   => 5
 });

Valid configuration items are:

=over 3

=item B<TicketDB>

This directive specifys the DBI URL string to use when connecting to the
database.  Also, you might consider overloading the B<dbi_connect> method to
handle setting up your db connection if you are creating a subclass of this
module.

example: dbi:Pg:dbname=test

=item B<TicketDBUser>

This directive specifys the username to use when connecting to the databse.

=item B<TicketDBPassword>

This directive specifys the password to use when connecting to the databse.

=item B<TicketTable>

This directive specifys the ticket hash table as well as the column name for
the hash.

Format: table_name:ticket_column_name:timestamp_column

Example: tickets:ticket_hash:ts

=item B<TicketUserTable>

This directive specifys the users table and the username and password column
names.

Format: table_name:username_column:password_column

Example: users:usrname:passwd

=item B<TicketPasswordStyle>

This directive specifys what type of passwords are stored in the database.  The
default is to use I<cleartext> passwords.  Currently supported password styles
are:

=over 3

=item I<cleartext>

This password style is just plain text passwords.  When using this password
style, the supplied user password is simply compared with the password stored
in the database.

=item I<md5>

This password style generates an MD5 hex hash of the supplied password before
comparing it against the password stored in the database.  Passwords should be
stored in the database by passing them through Digest::MD5::md5_hex().

=item I<crypt>

This password style uses traditional crypt() to encrypt the supplied password
before comparing it to the password saved in the database.

=back

=item B<TicketSecretTable>

This directive specifys the server secret table as well as the names of the 
secret data column and the version column.

Format: table_name:data_column:version_column

Example: ticketsecrets:sec_data:sec_version

=item B<TicketExpires>

This directive specifys the number of minutes that tickets should remain
valid for.  If a user exceeds this limit, they will be forced to log in
again.

=item B<TicketIdleTimeout>

This directive specifys the number of minutes of inactivity before a ticket
is considered invalid.  Setting this value to 5 for example would force a
re-login if no requests are recieved from the user in a 5 minute period.

The default for this value is 0, which disables this feature.  If this number
is larger than I<TicketExpires>, then this setting will have no effect.

=item B<TicketLogoutURI>

This directive specifys the URL that the user should be sent to after 
they are successfully logged out (this is done via a redirect).

Example: /logged_out_message.html

=back

=head2 Database Configuration

Three database tables are needed for this module:

=over 3

=item B<users table>

This table stores the actual usernames and passwords of the users.  This table
needs to contain at least a username and password column.  This table is
confgured by the I<TicketUserTable> directive.

 example:

 CREATE TABLE users (
     usename VARCHAR(32) NOT NULL,
     passwd  VARCHAR(32) NOT NULL
 );

=item B<tickets table>

This table stores the ticket hash for each ticket.  This information must be
stored locally so that users can be forcefully logged out without worrying if
the HTTP cookie doesn't get deleted.

 example:

 CREATE TABLE tickets (
    ticket_hash CHAR(32) NOT NULL,
    ts          INT NOT NULL,
    PRIMARY KEY (ticket_hash)
 );

=item B<secrets table>

This table contains the server secret and a numeric version for the secret.
This table is configured by the I<TicketSecretTable> directive.

 example:

 CREATE TABLE ticketsecrets (
     sec_version  SERIAL,
     sec_data     TEXT NOT NULL
 );

=back

=head1 METHODS

This is not a complete listing of methods contained in I<Apache2::AuthTicket>.
Rather, it is a listing of methods that you might want to overload if you were
subclassing this module.  Other methods that exist in the module are probably
not useful to you.

Feel free to examine the source code for other methods that you might choose to
overload.

=over 3

=item void make_login_screen($r, String action, String destination)

This method creats the "login" screen that is shown to the user.  You can
overload this method to create your own login screen.  The log in screen only
needs to contain a hidden field called "destination" with the contents of
I<destination> in it, a text field named I<credential_0> and a password field
named I<credential_1>.  You are responsible for sending the http header as well
as the content.  See I<Apache2::AuthCookie> for the description of what each of
these fields are for.

I<action> contains the action URL for the form.  You must set the action of
your form to this value for it to function correctly.

I<Apache2::AuthTicket> also provides a mechanism to determine why the login for
is being displayed.  This can be used in conjunction with
I<Apache2::AuthCookie>'s "AuthCookieReason" setting to determine why the user is
being asked to log in.  I<Apache2::AuthCookie> sets
$r->prev->subprocess_env("AuthCookieReason") to either "no_cookie" or
"bad_cookie" when this page is loaded.  If the value is "no_cookie" then the
user is being asked to log in for the first time, or they are logging in after
they previously logged out.  If this value is "bad_cookie" then
I<Apache2::AuthTicket> is asking them to re-login for some reason.  To determine
what this reason is, you must examine
$r->prev->subprocess_env("AuthTicketReason").  I<AuthTicketReason> can take the
following values:

=over 3

=item malformed_ticket

This value means that the ticket is malformed.  In other words, the ticket does
not contain all of the required information that should be present.

=item invalid_hash

This value means that the hash contained in the ticket does not match any
values in the tickets database table.  This might happen if you are
periodically clearing out old tickets from the database and the user presents a
ticket that has been deleted.

=item expired_ticket

This value means that the ticket has expired and the user must re-login to be
issued a new ticket.

=item missing_secret

This value means that the server secret could not be loaded.

=item idle_timeout

This value means that the user has exceeded the I<TicketIdleTimeout> minutes of
inactivity, and the user must re-login.

=item tampered_hash

This value indicates that the ticket data does not match its cryptographic
signature, and the ticket has most likely been tampered with.  The user is
forced to re-login at this point.

=back

You can use these values in your I<make_login_screen()> method to display a
message stating why the user must login (e.g.: "you have exceeded 5 minutes of
inactivity and you must re-login").

=item DBI::db dbi_connect()

This method connects to the TicketDB data source. You might overload this
method if you have a common DBI connection function. For example:

 sub dbi_connect {
     my ($this) = @_;
     return Foo::dbi_connect();
 }

Note that you can also adjust the DBI connection settings by setting TicketDB,
TicketDBUser, and TicketDBPassword in httpd.conf.

=back

=head1 BUGS

None known, but that doesn't mean there aren't any.  If you find a bug in this
software, please let me know.

=head1 CREDITS

The idea for this module came from the Ticket Access system in the eagle book,
along with several ideas discussed on the mod_perl mailing list.

Thanks to Ken Williams for his wonderful I<Apache2::AuthCookie> module, and for
putting in the necessary changes to I<Apache2::AuthCookie> to make this module
work!

=head1 AUTHOR

Michael Schout <mschout@gkg.net>

=head1 SEE ALSO

L<perl>, L<mod_perl>, L<Apache>, L<Apache2::AuthCookie>

=cut
