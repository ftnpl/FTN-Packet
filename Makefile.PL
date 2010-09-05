use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
#  the contents of the Makefile that is written.
WriteMakefile(
    NAME		=> 'FTN::Packet',
    AUTHOR              => 'Robert James Clay <jame@users.sf.net>',
    VERSION_FROM	=> 'lib/FTN/Packet.pm',
    ABSTRACT_FROM	=> 'lib/FTN/Packet.pm', 
    LICENSE        	=> 'perl',
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'FTN-Packet-*' },
);
