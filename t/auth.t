#!perl
#
# test AuthTicket authentication

use strict;
use warnings FATAL => 'all';
use Apache::Test ':withtestmore';
use Test::More;
use Apache::TestRequest qw(GET POST);

plan tests => 33, need_lwp;

# must match value in SQLite DB
my $Secret = 'mvkj39vek@#$R*njdea9@#';

use_ok('Apache::AuthTicket::Util');

Apache::TestRequest::user_agent(
    cookie_jar            => {},
    reset                 => 1,
    requests_redirectable => 0);

# get login form
my $r = GET '/protected/index.html';
isa_ok $r, 'HTTP::Response';
is $r->code, 403, 'got 403 response';
like $r->content, qr/credential_0/, 'content contains credential_0';
like $r->content, qr/credential_0/, 'content contains credential_1';

# login
$r = POST '/login', [
    destination => '/protected/index.html',
    credential_0 => 'programmer',
    credential_1 => 'secret' ];
isa_ok $r, 'HTTP::Response';
is $r->code, 302, 'got 302 response';
is $r->header('Location'), '/protected/index.html', 'Location header';
like $r->header('Set-Cookie'), qr/\buser:programmer\b/, 'response sets cookie';

# get the protected page.
$r = GET '/protected/index.html';
isa_ok $r, 'HTTP::Response';
is $r->code, 200, 'got 200 response';
like $r->content, qr/congratulations, you got the protected page/;

# logout
$r = GET '/protected/logout';
isa_ok $r, 'HTTP::Response';
is $r->code, 302, 'got 302 response from logout';
like $r->header('Set-Cookie'), qr/::AuthTicket_Protected=;\s+/, 'Cookie was cleared';

# make sure we really logged out.
$r = GET '/protected/index.html';
isa_ok $r, 'HTTP::Response';
is $r->code, 403, 'got 403 response';

### /secure auth area tests.
$r = GET '/secure/protected/index.html';
isa_ok $r, 'HTTP::Response';
is $r->code, 403, 'got 403 response';
like $r->content, qr/credential_0/, 'content contains credential_0';
like $r->content, qr/credential_0/, 'content contains credential_1';

# login
$r = POST '/secure/login', [
    destination => '/secure/protected/index.html',
    credential_0 => 'programmer',
    credential_1 => 'secret' ];
isa_ok $r, 'HTTP::Response';
is $r->code, 302, 'got 302 response';
is $r->header('Location'), '/secure/protected/index.html', 'Location header';
my $cookie = $r->header('Set-Cookie');
like $cookie, qr/\buser:programmer\b/, 'response sets cookie';
ok cookie_has_field($cookie, 'secure'), 'cookie has secure flag set';
ok cookie_has_field($cookie, 'path=/secure'), 'cookie path = /secure';
ok cookie_has_field($cookie, 'domain=.local'), 'cookie domain is .local';
ok check_hash($cookie, ip => 0, browser => 1), 'hash users browser, not ip';

# we have to manually send the cookie here because of secure/domain fields.
$r = GET '/secure/protected/index.html', Cookie => $cookie;
isa_ok $r, 'HTTP::Response';
is $r->code, 200, 'got 200 response';

# lets tamper with the cookie. should get 403
$cookie =~ s/expires:(\d+)/sprintf 'expires:%d', $1+1/e;
$r = GET '/secure/protected/index.html', Cookie => $cookie;
isa_ok $r, 'HTTP::Response';
is $r->code, 403, 'tampered cookie got 403 response';

sub cookie_has_field {
    my ($cookie, $expected) = @_;

    my @parts = split /;\s+/, $cookie;

    for my $part (@parts) {
        return 1 if lc $part eq lc $expected;
    }

    return 0;
}

# given a cookie string, recompute the hash and check that it is what we expect.
# options:
#   ip => 0|1      ticket includes ipaddress
#   browser => 0|1 ticket includes user agent string
sub check_hash {
    my ($cookie, %opt) = @_;

    my ($string) = $cookie =~ /AuthTicket_[^=]+=(.*?);/;

    my %ticket = split /:/, $string;

    my @fields = ($Secret,
        @ticket{qw(version time expires user)});

    if ($opt{ip}) {
        push @fields, '127.0.0.1';
    }

    if ($opt{browser}) {
        push @fields, Apache::TestRequest::user_agent()->agent;
    }

    my $hash = Apache::AuthTicket::Util::hash_for(@fields);

    unless ($hash eq $ticket{hash}) {
        diag "Hash mismatch: $hash != $ticket{hash}";
        return 0;
    }

    return 1;
}

# vim: ft=perl
