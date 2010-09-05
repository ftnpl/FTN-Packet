#!perl -T

use Test::More tests => 2;

BEGIN {
	use_ok( 'FTN::Packet' );
}

diag( "Testing FTN::Packet $FTN::Packet::VERSION, Perl $], $^X" );
