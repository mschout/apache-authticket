use ExtUtils::MakeMaker;
use lib qw(t/lib);
use My::Util qw(mod_perl_version);

require 5.6.0;

my @CLEAN_FILES = ();
my $mp_version = mod_perl_version();
test_configure();

my %prereq = (
    'Apache::Test'  => 1.22,
    'DBI'           => 0,
    'DBD::SQLite'   => 0, # XXX for tests, dev release only
    'Digest::MD5'   => 0,
    'SQL::Abstract' => 0,
    'Test::More'    => 0
);

if ($mp_version == 2) {
    # MP2 deps
    $prereq{'mod_perl2'} = '1.9922';  # mod_perl -> modperl2
    $prereq{'Apache2::AuthCookie'} = '3.0';
}
else {
    # MP2 deps
    $prereq{'mod_perl'} = '1.27';
    $prereq{'Apache::AuthCookie'} = '3.0';
}

WriteMakefile(
    NAME          => 'Apache::AuthTicket',
    VERSION_FROM  => 'lib/Apache/AuthTicket.pm',
    AUTHOR        => 'Michael Schout <mschout@gkg.net>',
    ABSTRACT      => 'Ticket based authentication system for Apache',
    PREREQ_PM     => \%prereq,
    clean         => {
        FILES => \@CLEAN_FILES
    }
);

sub test_configure {
    if (eval { require Apache::TestMM }) {
        # enable make test
        Apache::TestMM->import(qw(test clean));

        Apache::TestMM::filter_args;

        Apache::TestMM::generate_script('t/TEST');

        push @CLEAN_FILES, 't/TEST';
    }
    else {
        # overload test rule with a no-op
        warn "***: You should install Apache::Test to do real testing\n";
        *MY::test = sub {
            return <<'EOF';
test : pure_all
»···@echo \*** This test suite requires Apache::Test available from CPAN
EOF
        };
    }
}

# :vim set ts=4 sw=4 ai et
