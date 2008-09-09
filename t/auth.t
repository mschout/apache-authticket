#!perl
#
# test AuthTicket authentication

use strict;
use warnings FATAL => 'all';
use Apache::Test ':withtestmore';
use Test::More;
use Apache::TestRequest qw(GET POST);

plan tests => 16, need_lwp;

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

# vim: ft=perl
