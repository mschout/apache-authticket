use ExtUtils::MakeMaker;
use ExtUtils::Manifest qw(maniread);

BEGIN { require 5.004 }

sub chk_version {
    my ($pkg, $wanted) = @_;

    $! = 1;
    print "Checking for $pkg";
		print " >= $wanted" if $wanted;
		print "...";

    eval { 
        my $p; 
        ($p = $pkg.".pm") =~ s#::#/#g; 
        require $p;
    };

    my $vnum = ${"${pkg}::VERSION"} || 0;
    my $vstr = $vnum ? "found v$vnum"
                     : "not found";

    print $vnum >= $wanted ? "ok\n" : " " . $vstr . "\n";

    $vnum >= $wanted;
}

#--- Check dependencies
chk_version( 'Apache::AuthCookie' => 2.011 ) or 
	die "\n"
	."You need Apache::AuthCookie version 2.011 or later "
	."to install this module\n\n";

chk_version( 'DBI' => 0 ) or 
    die "\n"
    ."You need to have DBI installed in order to install this module\n\n";

chk_version( 'Digest::MD5' => 0 ) or 
    die "\n"
    ."You need to have Digetst::MD5 installed in order to "
    ."install this module\n\n";

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME          => 'Apache::AuthTicket',
    VERSION_FROM  => 'AuthTicket.pm',
    AUTHOR        => 'Michael Schout <mschout@gkg.net>',
    ABSTRACT      => 'Ticket based authentication system for Apache'
);
