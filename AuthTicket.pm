#
# $Id$
#

package Apache::TicketAccess;

use strict;
use vars qw($VERSION %DEFAULTS %CONFIG);

use Apache::Constants qw(OK FORBIDDEN REDIRECT SERVER_ERROR);
use Apache::Util ();
use Apache::File ();
use Apache::URI ();
use Apache::Cookie ();
use Apache::Request ();
use DBI ();
use Digest::MD5 ();

$VERSION = '0.01';

%DEFAULTS = (
    TicketDB              => 'dbi:Pg:dbname=template1',
    TicketDBUser          => 'test',
    TicketDBPassword      => 'test',
    TicketTable           => 'tickets:ticket_hash',
    TicketUserTable       => 'users:usrname:passwd',
    TicketSecretTable     => 'ticketsecrets:sec_data:sec_version',
    TicketExpires         => 15,
    TicketDomain          => '',
    TicketPath            => '/',
    TicketSecure          => '0',
    TicketTimeLimit       => 30,
    TicketRefresh         => 'On',
    TicketLoginForm       => '/loginform',
    TicketLoginScript     => '/login',
    TicketLogoutURI       => '/',
    TicketRefreshInterval => 30
);

my $DEBUG = 0;

sub new {
    my ($class, $r) = @_;
    $class = ref $class || $class;
    my $this = bless { _r => $r }, $class;
    $this->init($r);
    return $this;
}

sub init {
    my ($this, $r) = @_;
    die 'usage: '.__PACKAGE__.'->new($r)'."\n" unless defined $r;
    $this->request($r);

    my $label = $r->dir_config('TicketRealm');
    $this->realm($label);

    for my $i (keys %DEFAULTS) {
        $this->{$i} = $CONFIG{$label}->{$i} || $r->dir_config($i) ||
            $DEFAULTS{$i};
    }
}

sub request {
    my ($this, $value) = @_;
    $this->{request} = $value if defined $value;
    $this->{request};
}

sub realm {
    my ($this, $value) = @_;
    $this->{realm} = $value if defined $value;
    $this->{realm};
}

#
# here we provide a way to configure the package via perl
# instead of adding unnecessary cruft to your configuration file.
#
# usage: class->configure(realm, \%options)
#
sub configure {
    my ($class, $label, $args) = @_;

    Apache->push_handlers( PerlChildInitHandler =>
        sub {
            $CONFIG{$label} = {};

            for my $i (keys %$args) {
                die "invalid config item: $i\n" unless defined $DEFAULTS{$i};

                $CONFIG{$label}->{$i} = $args->{$i};
            }
        }
    );
}

sub authenticate ($$) {
    my ($class, $r) = @_;

    my $this = $class->new($r);
    my ($result, $msg) = $this->verify_ticket($r);

    return $this->go_to_login_form($msg) unless $result;

    $r->log_error("Ticket is valid") if $DEBUG;

    return OK;
}

sub login_form ($$) {
    my ($class, $r) = @_;

    if (lc $r->dir_config('Filter') eq 'on') {
        $r->filter_input(handle=>1);
    }

    my $this = $class->new($r);

    my $apr = Apache::Request->new($r);

    my $action = $this->{TicketLoginScript};
    my $request_uri = $apr->param('request_uri') || $r->prev->uri;

    my $msg = $apr->param('message');
    $this->make_login_screen($r, $action, $request_uri, $msg);

    return OK;
}

sub login ($$) {
    my ($class, $r) = @_;

    if (lc $r->dir_config('Filter') eq 'on') {
        $r->filter_input(handle=>1);
    }

    my $this = $class->new($r);

    my $apr = Apache::Request->new($r);

    my ($user, $pass, $dest) = 
        map { $apr->param($_) } qw/username password request_uri/;

    my $action = $this->{TicketLoginScript};
    my $request_uri = $apr->param('request_uri') || $r->prev->uri;

    my ($result, $msg) = $this->check_credentials($user, $pass);
    if ($result) {
        my $ticket = $this->make_ticket($r, $user);
        unless ($ticket) {
            $r->log_error("Couldn't make ticket -- missing secret?");
            return SERVER_ERROR;
        }
        $r->err_headers_out->add('Location' => $dest);
        return REDIRECT;
    } else {
        $this->make_login_screen($r, $action, $request_uri, $msg);
        return OK;
    }
}

sub logout ($$) {
    my ($class, $r) = @_;

    if (lc $r->dir_config('Filter') eq 'on') {
        $r->filter_input(handle=>1);
    }

    my $this = $class->new($r);

    $this->expire_ticket($r);

    if ($DEBUG) {
        my %head = $r->err_headers_out;
        for my $hdr (keys %head) {
            $r->log_error("$hdr: $head{$hdr}");
        }
    }

    $r->err_headers_out->add('Location' => $this->{TicketLogoutURI});
    return REDIRECT;
}

sub get_config {
    my ($this, $realm) = @_;
    return $CONFIG{$realm};
}

sub go_to_login_form {
    my ($this, $msg) = @_;

    my $r = $this->request;

    $r->log_reason($msg, $r->filename);
    my $uri = Apache::URI->parse($r, $this->{TicketLoginForm});
    $uri->query( Apache::Util::escape_uri("message=$msg") );
    $r->log_error("URI: ".$uri->unparse) if $DEBUG;
    $r->custom_response(FORBIDDEN, $uri->unparse);
    return FORBIDDEN;
}

#-----------------------------------------------------------------------------

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

sub check_credentials {
    my ($this, $user, $password) = @_;
    $this->{_r}->log_error("in TicketAccess::check_credentials()") if $DEBUG;

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
    $r->log_error('in TicketAccess::verify_ticket()') if $DEBUG;

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

Apache::TicketAccess - Cookie based access module.

=head1 SYNOPSIS

 # in httpd.conf
 <Location /protected>
   PerlAccessHandler Apache::TicketAccess->authenticate
   PerlSetVar        TicketRealm protected
 </Location>

 <Location /loginform>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->login_form
   PerlSetVar  TicketRealm protected
 </Location>

 <Location /login>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->login
   PerlSetVar  TicketRealm protected
 </Location>

 <Location /protected/logout>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->logout
   PerlSetVar  TicketRealm protected
 </Location>

 # in startup.pl
 Apache::TicketAccess->configure('protected', {
     TicketUserTable       => 'users:usenaem:passwd',
     TicketTable           => 'tickets:ticket_hash',
     TicketSecretTable     => 'ticketsecrets:sec_data:sec_version',
     TicketDomain          => '.foo.com',
     TicketPath            => '/protected',
     TicketSecure          => 1,
     TicketLoginForm       => '/loginform',
     TicketLoginScript     => '/login',
     TicketExpires         => 15
 });

=head1 DESCRIPTION

This module provides ticket based access control.  The theory behind this is
similar to the system described in the eagle book. 

This module works using HTTP cookies to check if a user is authorized to view a
page.  If a cookie named I<Ticket> exists, then the ticket is verified to
ensure that the ticket is valid.  If the ticket is found to be invalid, then
the user is redirected to the URL specified by I<TicketLoginForm>, and access
to the requested page is denied.

This module was desigend to be as extensible as possible.  Its quite likely
that you will want to create your own subclass of I<Apache::TicketAccess> in
order to customize various aspects of this module (show your own versions of
the forms, override database methods etc). 

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
process will still allow tickets to be authorized as long as they exist in the
tickets table. 

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

=head1 CONFIGURATION

There are two things you must do in order to configure this module: 

 1) configure your mod_perl apache server
 2) create the necessary database tables.

=head2 Apache Configuration - httpd.conf

There are two ways that this module could be configured.  Either by using a
function call in startup.pl, or by configuring each handler explicitly in
httpd.conf.  By using the startup.pl method, the amout of duplicated
information in httpd.conf is greatly reduced.  As such, I do not discuss this
method here.  I recommend using the startup.pl method, and this is what is
discussed here.

There are four blocks that need to be entered into httpd.conf.  The first of
these is the block specifying your access restrictions.  This block should look
somrthing like this:

 <Location /protected>
   PerlAccessHandler Apache::TicketAccess->authenticate
   PerlSetVar        TicketRealm protected
 </Location>

I<TicketRealm> is just a label that is used to tell Apache::TicketAccess which
configuration to use for this block.

This specifys that any URL in /protected must pass authentication through
I<Apache::TicketAccess>.  Directory blocks should also work fine here (although
I have not tested this).

The remaining blocks control how to display the login form, and the login and
logout urls.  These blocks should look similar to this:

 <Location /loginform>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->login_form
   PerlSetVar  TicketRealm protected
 </Location>

 <Location /login>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->login
   PerlSetVar  TicketRealm protected
 </Location>

 <Location /protected/logout>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->logout
   PerlSetVar  TicketRealm protected
 </Location>

It should be noted that Apache::TicketAccess is Apache::Filter aware.  So if
you implement your own subclass of Apache::TicketAccess that emits SSI tags,
you could do something like this:

 <Location /loginform>
   SetHandler  perl-script
   PerlHandler Apache::TicketAccess->login_form Apache::SSI
   PerlSetVar  TicketRealm protected
   PerlSetVar  Filter      On
 </Location>

=head2 Apache Configuration - startup.pl

Any TicketAccess configuration items can be set in startup.pl.  You can
configure a TicketRealm using:

 Apache::TicketAccess->configure(String realm, *Hash config)

config is a reference to a hash specifying configuation values.

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

Format: table_name:column_name

Example: tickets:ticket_hash

=item B<TicketUserTable>

This directive specifys the users table and the username and password column
names.

Format: table_name:username_column:password_column

Example: users:usrname:passwd

=item B<TicketSecretTable>

This directive specifys the server secret table as well as the names of the 
secret data column and the version column.

Format: table_name:data_column:version_column

Example: ticketsecrets:sec_data:sec_version

=item B<TicketExpires>

This directive specifys the number of minutes that tickets should remain
valid for.  If a user exceeds this limit, they will be forced to log in
again.

=item B<TicketDomain>

This directive specifys the "domain" field to pass with the Ticket cookie.

=item B<TicketPath>

this directive specifys the "path" field to pass with the Ticket cookie.

=item B<TicketSecure>

This directive specifys if the "secure" flag should be set with the Ticket
cookie.  If this is set to a true value, then the cookies will only be sent
over SSL connections.

=item B<TicketLoginForm>

This directive specifys the URL of the login form.

Example: /loginform

=item B<TicketLoginScript>

This directive specifys the directive of the login handler

Example: /login

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
the HTTP cookie doesn't get deleted.  This table only needs a character field
that is 32 characters long to store the hash.  Its likely that you will also
want to save a timestamp with each hash so that you can delete old tuples from
this table periodically.

 example:

 CREATE TABLE tickets (
    ticket_hash CHAR(32) NOT NULL PRIMARY KEY,
    ts          TIMESTAMP NOT NULL DEFAULT NOW()
 );

=item B<secrets table>

This table contains the server secret and a numeric version for the secret.
This table is configured by the I<TicketSecretTable> directive.

 example:

 CREATE TABLE ticketsecrets (
     sec_version  SERIAL,
     sec_ts       TIMESTAMP NOT NULL DEFAULT NOW(),
     sec_data     TEXT NOT NULL
 );

=back

=head1 METHODS

This is not a complete listing of methods contained in I<Apache::TicketAccess>.
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

The idea for this module came from the Ticket Access system in the eagle book,
along with several ideas discussed on the mod_perl mailing list.

=head1 AUTHOR

Michael Schout <mschout@gkg.net>

=cut
