#
# TODO:
#    o Reset the auth ticket for each request so it does not expire until
#      TicketExpire time of inactivity elapses (make this configable?)
#    o More Testing
#    o BUG: If client refuses thecookies, they dont get the no-cookies error.

package Apache::TicketTool;

use strict;
use Apache::TicketAccess ();
use Apache::Cookie ();
use Apache::File ();
use Apache::URI ();
use DBI ();
use Digest::MD5 ();

my $DEBUG = 0;

sub new {
    my ($class, $r) = @_;
    $class = ref $class || $class;

    my $this = bless { _r => $r }, $class;

    my $realm = $r->dir_config('TicketRealm');
    my $config = Apache::TicketAccess->get_config($realm);

    $r->log_error("TT CONFIG: ".join(' ', %$config)) if $DEBUG;

    foreach my $param (keys %Apache::TicketAccess::DEFAULTS) {
        $this->{$param} = $config->{$param} || $r->dir_config($param);
    }

    return $this;
}

sub dbi_connect {
    my ($this) = @_;

    my $dbh = DBI->connect($this->{TicketDB},
                           $this->{TicketDBUser},
                           $this->{TicketDBPassword});

    return $dbh;
}

# boolean check_user(String username)
#
# return true if a username exists.
sub check_user {
    my ($this, $user) = @_;

    my $dbh = $this->dbh;

    my $rows = 0;

    my ($table, $user_field) = split(/:/, $this->{TicketUserTable});
    my $query = qq{
        SELECT  COUNT(*)
        FROM    $table
        WHERE   $user_field = ?
    };

    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($user);
        $sth->bind_columns(\$rows);
        $sth->fetch;
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

    my $dbh = $this->dbh;

    my ($table, $user_field, $passwd_field) = 
        split(/:/, $this->{TicketUserTable});

    my $query = qq{
        SELECT  $passwd_field
        FROM    $table
        WHERE   $user_field = ?
    };

    my $passwd = undef;
    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($user);
        $sth->bind_columns(\$passwd);
        $sth->fetch;
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return $passwd;
}

#
# get or set the DBI handle
# 
# will automatically call this->dbi_connect on the first call
sub dbh {
    my ($this) = @_;
    $this->{_DBH} = $this->dbi_connect() if not defined $this->{_DBH};
    $this->{_DBH};
}

# overload this to make your own login sscren
sub make_login_screen {
    my ($this, $r, $action, $request_uri, $msg) = @_;

    $r->content_type('text/html');

    $r->send_http_header() unless (lc $r->dir_config('Filter') eq 'on');

    $r->print(
        q{<!DOCTYPE HTML PUBLIC  "-//W3C//DTD HTML 3.2//EN">},
        q{<HTML>},
        q{<HEAD>},
        q{<TITLE>Log in</TITLE>},
        q{</HEAD>},
        q{<BODY bgcolor="#ffffff">},
        q{<H1>Please Log In</H1>}
    );

    if (defined $msg and $msg) {
        $r->print(qq{<h2><font color="#ff0000">Error: $msg</font></h2>});
    }

    $r->print(
        qq{<form method="post" action="$action">},
        qq{<input type="hidden" name="request_uri" value="$request_uri">}.
        q{<table>},
        q{<tr>},
        q{<td>Name</td>},
        q{<td><input type="text" name="username"></td>},
        q{</tr>},
        q{<tr>},
        q{<td>Password</td>},
        q{<td><input type="password" name="password"></td>},
        q{</tr>},
        q{</table>},
        q{<input type="submit" value="Log In">},
        q{<p>},
        q{</form>},
        q{<EM>Note: </EM>},
        q{Set your browser to accept cookies in order for login to succeed.},
        q{You will be asked to log in again after some period of time.}
    );
}

sub authenticate {
    my ($this, $user, $password) = @_;
    $this->{_r}->log_error("in TicketTool::authenticate()") if $DEBUG;

    my ($table, $user_field, $pass_field) = 
        split(/:/, $this->{TicketUserTable});

    my $dbh = $this->dbh;

    return (undef, "Can't open database: $DBI::errstr") unless $dbh;

    return (undef, "invalid account") unless $this->check_user($user);

    # we might add an option for crypt or MD5 style password someday
    my $saved_passwd = $this->get_password($user);

    return (undef, "password mismatch") unless $saved_passwd eq $password;

    # its valid.
    return (1, '');
}

#
# ($secret, $version) = $obj->fetch_secret();
# ($secret, $version) = $obj->fetch_secret($ver);
#
sub fetch_secret {
    my ($this, $version) = @_;

    my $dbh = $this->dbh;

    my ($secret_table, $secret_field, $secret_version_field) =
        split(/:/, $this->{TicketSecretTable});

    my $query;
    if (defined $version) {
        $query = qq{
            SELECT  $secret_field, $secret_version_field
            FROM    $secret_table
            WHERE   $secret_version_field = ?
        };
    } else {
        # hopefully this is not too db specific.  it works in Mysql and Pgsql
        $query = qq{
            SELECT   $secret_field, $secret_version_field
            FROM     $secret_table
            ORDER BY $secret_version_field DESC
            LIMIT 1
        };
    }

    my ($secret, $ret_version) = (undef, undef);
    eval {
        my $sth = $dbh->prepare($query);
        if (defined $version) {
            $sth->execute($version);
        } else {
            $sth->execute;
        }
        $sth->bind_columns(\$secret, \$ret_version);
        $sth->fetch;
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

    my $now      = time();
    my $expires  = $now + $this->{TicketExpires} * 60;
    my $ip       = $r->connection->remote_ip;
    my ($secret, $sec_version) = $this->fetch_secret();

    my $hash = Digest::MD5->md5_hex($secret .
                   Digest::MD5->md5_hex(join ':', $secret, $ip, $sec_version, 
                                        $now, $expires, $user_name)
               );

    my %key = (
        'version' => $sec_version,
        'time'    => $now,
        'user'    => $user_name,
        'expires' => $expires,
        'hash'    => $hash
    );

    $this->save_hash($key{'hash'});

    my $cookie = Apache::Cookie->new($r,
                         -name    => 'Ticket',
                         -value   => \%key,
                         -domain  => $this->{TicketDomain},
                         -path    => $this->{TicketPath},
                         -secure  => $this->{TicketSecure});


    $cookie->bake;
    $r->log_error("MAKE TICKET: ".$cookie->as_string) if $DEBUG;
    return $cookie
}

# invalidate the ticket by expiring the cookie, and delete the hash locally
sub expire_ticket {
    my ($this, $r) = @_;

    my $cookie = Apache::Cookie->new($r);
    my %cookies = $cookie->fetch;

    return undef unless defined $cookies{'Ticket'};

    my $tcookie = $cookies{'Ticket'};
    my %ticket = $tcookie->value;
    $this->delete_hash($ticket{'hash'});

    # try to coax the browser to discard the cookie
    $tcookie->expires('-5y');
    $tcookie->bake;
}

# Apache::Cookie get_ticket()
sub get_ticket {
    my ($this, $r) = @_;

    my $cookie = Apache::Cookie->new($r);
    my %cookies = $cookie->fetch;
    return $cookies{'Ticket'}
}

#
# boolean check_ticket_format(%ticket)
#
# return true if the ticket contains the required fields.
#
sub check_ticket_format {
    my ($this, %key) = @_;

    $this->{_r}->log_error("key is ".join(' ', %key)) if $DEBUG;
    for my $param (qw(version time user expires hash)) {
        return 0 unless defined $key{$param};
    }

    return 1;
}

#
# (boolean, String) verify_ticket($r)
#
# Verify the ticket and return true or false.
# A string containing the reason for the failure is returned if the
# ticket is invalid.
#
sub verify_ticket {
    my ($this, $r) = @_;
    $r->log_error('in TicketTool::verify_ticket()') if $DEBUG;

    my $cookie = Apache::Cookie->new($r);
    my %cookies = $cookie->parse;

    unless (%cookies) {
        # no cookies
        return (0, '');
    }
    unless ($cookies{'Ticket'}) {
        # no ticket
        return (0, '');
    }

    my %ticket = $cookies{'Ticket'}->value;
    my ($secret, $sec_version);

    unless ($this->check_ticket_format(%ticket)) {
        return (0, 'malformed ticket');
    }
    unless ($this->is_hash_valid($ticket{'hash'})) {
        return (0, '');
    }
    unless ($r->request_time < $ticket{'expires'}) {
        return (0, 'ticket has expired');
    }
    unless (($secret, $sec_version) = $this->fetch_secret($ticket{'version'})) {
        return (0, 'can\'t retrieve secret');
    }

    # create a new hash and verify that it matches the supplied hash
    # (prevents tampering with the cookie)
    my $ip = $r->connection->remote_ip;
    my $newhash = Digest::MD5->md5_hex($secret .
                      Digest::MD5->md5_hex(join ':', $secret, $ip,
                          @ticket{qw(version time expires user)})
                  );

    unless ($newhash eq $ticket{'hash'}) {
        return (0, 'ticket mismatch');
    }

    $r->connection->user($ticket{'user'});

    return (1, 'ok');
}

########## SERVER SIDE HASH MANAGEMENT METHODS

#
# save the ticket hash in the db
#
sub save_hash {
    my ($this, $hash) = @_;

    my ($table, $field) = split(/:/, $this->{TicketTable});
    my $dbh = $this->dbh;

    my $query = qq{ INSERT INTO $table ($field) VALUES (?) };
    warn "QUERY: $query [hash=$hash]\n";

    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($hash);
        $dbh->commit;
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

    my ($table, $field) = split(/:/, $this->{TicketTable});
    my $dbh = $this->dbh;

    my $query = qq{
        DELETE
        FROM    $table
        WHERE   $field = ?
    };

    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($hash);
        $dbh->commit;
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

    my ($table, $field) = split(/:/, $this->{TicketTable});
    my $dbh = $this->dbh;

    my $query = qq{
        SELECT  $field
        FROM    $table
        WHERE   $field = ?
    };

    my $value = undef;
    eval {
        my $sth = $dbh->prepare($query);
        $sth->execute($hash);
        ($value) = $sth->fetchrow_array;
    };
    if ($@) {
        $dbh->rollback;
        die $@;
    }

    return (defined $value and $value eq $hash) ? 1 : 0;
}


1;

__END__

=head1 NAME

Apache::TicketTool - Utility module for Ticket Access system.

=head1 SYNOPSIS

  # none really. Just subclass this if you want to overload methods.

=head1 DESCRIPTION

This module does most of the dirty work for the Ticket Access system.

This system uses cookies to authenticate users.  When a user is authenticated
throught this system, they are issued a cookie consisting of the time, the
username of the user, the expriation time of hte cookie, a "secret" version
(described later), and a cryptographic signature.  The cryptographic signature
is generated using the MD5 algorithm on the cookie data and a "secret" key that
is read from a database.  Each secret key also has a version number associated
with it.  This allows the site administrator to issue a new secret periodically
without invalidating the current valid tickets.   For example, the site
administrator might periodically insert a new secret key into the databse
periodically, and flush secrets that are more than 2 days old.  Since the 
ticket issued to the user contains the secret version, the authentication
process will still allow tickets to be authorized as long as they
exist in the tickets table. 

The actual contents and length of secret data is left to the site
administrator. A good choice might be to read data from /dev/random, unpack it
into a hex string and save that.

This system should be reasonably secure becuase the IP address of the end user
is incorporated into the cryptographic signature. If the ticket were
intercepted, then an aattacker would have to steal the user's IP address in
order to be able to use the ticket.  Plus, since the tickets can expire
automatically, we can be sure that the ticket is not valid for a long period of
time.  Finally, by setting I<TicketSecure> to a true value, the ticket is not
passed over unencrypted connections.  In order to attack this system, an
attacker would have to exploit both the MD5 algoright as well as SSL. Chances
are, by the time the user could break both of these, the ticket would no longer
be valid.

=head1 METHODS

This is not a complete listing of methods contained in I<Apache::TicketTool>.
Rather, it is a listing of methods that you might want to overload if you were
subclassing this module.  Other methods that exist in the module are probably
not useful to you.

Feel free to examine the source code for other methods that you might choose to
overload.

=over 3

=item void make_login_screen($r, String action, String request_uri, String message)

This method creats the "login" screen that is shown to the user.  You can
overload this method to create your own login screen.  The log in screen only
needs to contain a hidden field called "request_uri" with the contents of
I<request_uri> in it, a text field named "username" and a password field named
"password".  You are responsible for sending the http header as well as the
content.  

I<action> contains the action URL for the form.  You must set the action of
your form to this value for it to function correctly.

I<message> will contain an error message if the user was unable to
log in or if the user was automatically logged out.  You can ignore I<message>
if you dont wish to show this information to your users.

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

=head1 CREDITS

This module was influenced greatly from the TicketAccess system described in
the eagle book.

=head1 AUTHOR

Michael Schout <mschout@gkg.net>

=head1 SEE ALSO

Apache::TicketAccess

=cut
