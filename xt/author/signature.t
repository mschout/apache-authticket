#!perl -w

## Test that our SIGNATURE file is valid

use strict;
use warnings;
use Test::More;

unless (eval { require Test::Signature; 1 }) {
    plan skip_all => 'Test::Signature is required for this test.';
}

Test::Signature::signature_ok();
done_testing;
