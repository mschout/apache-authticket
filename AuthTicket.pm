#
# $Id$
#

package Apache::TicketAccess;

use strict;
use vars qw($VERSION %DEFAULTS %CONFIG);

use Apache::Constants qw(OK FORBIDDEN REDIRECT SERVER_ERROR);
use Apache::Util ();
use Apache::TicketTool ();
use Apache::Cookie ();
use Apache::Request ();

$VERSION = '0.01';

# just a couple of defaults.  We dont care about most of the config
# items in this module.  See TickeTool for a full list.
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
    TicketToolClass       => 'Apache::TicketTool',
    TicketRefresh         => 'On',
    TicketLoginForm       => '/loginform',
    TicketLoginScript     => '/login',
    TicketLogoutURI       => '/',
    TicketRefreshInterval => 30
);

my $DEBUG = 0;

sub new {
    my ($class, @args) = @_;
    $class = ref $class || $class;
    my $this = {};
    bless $this, $class;
    $this->init(@args);
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

            warn "configuring $label\n";
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
    my $tt = $this->new_ticket_tool($r);
    my ($result, $msg) = $tt->verify_ticket($r);

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

    my $tt = $this->new_ticket_tool;
    my $apr = Apache::Request->new($r);

    my $action = $this->{TicketLoginScript};
    my $request_uri = $apr->param('request_uri') || $r->prev->uri;

    my $msg = $apr->param('message');
    $tt->make_login_screen($r, $action, $request_uri, $msg);

    return OK;
}

sub login ($$) {
    my ($class, $r) = @_;

    if (lc $r->dir_config('Filter') eq 'on') {
        $r->filter_input(handle=>1);
    }

    my $this = $class->new($r);

    my $tt = $this->new_ticket_tool;
    my $apr = Apache::Request->new($r);

    my ($user, $pass, $dest) = 
        map { $apr->param($_) } qw/username password request_uri/;

    my $action = $this->{TicketLoginScript};
    my $request_uri = $apr->param('request_uri') || $r->prev->uri;

    my ($result, $msg) = $tt->authenticate($user, $pass);
    if ($result) {
        my $ticket = $tt->make_ticket($r, $user);
        unless ($ticket) {
            $r->log_error("Couldn't make ticket -- missing secret?");
            return SERVER_ERROR;
        }
        $r->err_headers_out->add('Location' => $dest);
        return REDIRECT;
    } else {
        $tt->make_login_screen($r, $action, $request_uri, $msg);
        return OK;
    }
}

sub logout ($$) {
    my ($class, $r) = @_;

    if (lc $r->dir_config('Filter') eq 'on') {
        $r->filter_input(handle=>1);
    }

    my $this = $class->new($r);
    my $tt   = $this->new_ticket_tool;

    $tt->expire_ticket($r);

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

sub new_ticket_tool {
    my ($this) = @_;
    my $r = $this->request;
    my $class = $this->{TicketToolClass};
    return $class->new($r);
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
     TicketToolClass       => 'Apache::TicketTool',
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
page.  If a cookie named I<Ticket> exists, then I<Apache::TicketTool> is used
to verify that the ticket is valid.  If the ticket is found to be invalid, then
the user is redirected to the URL specified by I<TicketLoginForm>, and access
to the requested page is denied.

I<Apache::TicketMaster> handles the actual login, logout, and authentication
logic.

This module was desigend to be as extensible as possible.  Its quite likely
that you will want to create your own subclass of I<Apache::TicketTool> in
order to customize various aspects of this module (show your own versions of
the forms, override database methods etc).  See I<Apache::TicketTool> for more
information about how this module behaves.

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
you implement your own subclass of Apache::TicketTool that emits SSI tags, you
could do something like this:

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
database.  Also see Apache::TicketTool for overloading database methods.

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

=item B<TicketToolClass>

This directive specifys the name of the TicketTool class to use.  If you 
have created your own subclass of Apache::TicketTool, then you must set
this directive to the class name of that subclass in order to make sure that
your TicketTool class will be used.

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

=head1 CREDITS

The idea for this module came from the Ticket Access system in the eagle book,
along with several ideas discussed on the mod_perl mailing list.

=head1 AUTHOR

Michael Schout <mschout@gkg.net>

=head1 SEE ALSO

Apache::TicketTool

=cut
