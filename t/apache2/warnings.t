#!perl
#
# test for warnings in Apache::AuthTicket
#

use strict;
use lib qw(t/lib lib);
use Test::More;
use My::Util 'mod_perl_version';

BEGIN {
    unless (eval "use Test::Warn; 1") {
        plan skip_all => 'Test::Warn not installed';
    }
}

unless (mod_perl_version() == 2) {
    plan skip_all => 'mod_perl version 2 required for this test';
}
else {
    plan tests => 3;
}

SKIP: {
    use_ok('Apache2::AuthTicket') or exit;

    # _unpack_ticket() should not warn with undef key.
    warning_is { Apache2::AuthTicket->_unpack_ticket() } undef;

    # unpacking ticket with odd number of elements should not warn
    warning_is { my %x = Apache2::AuthTicket->_unpack_ticket('foo') } undef;
}
