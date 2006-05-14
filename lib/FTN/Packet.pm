package FTN::Packet;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

=head1 NAME

FTN::Packet - Reading or writing Fidonet Technology Networks (FTN) packets.

=head1 VERSION

VERSION 0.07

=cut

$VERSION = '0.07';

=head1 DESCRIPTION

FTN::Packet is a Perl extension for reading or writing Fidonet Technology Networks (FTN) packets.

=cut

require Exporter;
require AutoLoader;

=head1 EXPORT

The following functions are available in this module:  read_ftn_packet(),
write_ftn_packet().

=cut

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
@EXPORT_OK = qw( &read_ftn_packet(), &write_ftn_packet()
	
);

=head1 FUNCTIONS

=head2 read_ftn_packet

Syntax:  $messages = read_ftn_packet(*PKT);

Read a Fidonet/FTN packet.  Returns the messages in the packet as a reference
to an array of hash references, which can be read as follows:

    $msg_ref = pop(@{$messages});
    $msg_area = ${$msg_ref}->('area');
    $msg_date = ${$msg_ref}->('ftnscdate');
    $msg_tonode = ${$msg_ref}->('tonode');
    $msg_from = ${$msg_ref}->('from');
    $msg_body = ${$msg_ref}->('to');
    $msg_subj = ${$msg_ref}->('subj');
    $msg_msgid = ${$msg_ref}->('msgid');
    $msg_replyid = ${$msg_ref}->('replyid');
    $msg_body = ${$msg_ref}->('body');
    $msg_ctrl = ${$msg_ref}->('ctrlinfo');

=cut

###############################################
# Read Messages from FTN packet 
###############################################
sub read_ftn_packet {

    my ($PKT) = @_;
    # "$PKT" is a file pointer to the packet file being read
    # Returns an array of hash references

    my ($PKTver,$orgnode,$destnode,$orgnet,$destnet,$attrib,$cost,$buf);
    my ($osep, $s, $datetime, $to, $from, $subj, $area, @lines, @kludges,
	$fromnode, $tonode, @messages, $msgbody, $msgid, $replyid, $origin,
	 $mailer, $seenby, $i, $k);

    read($PKT,$buf,58);  	# Ignore packet header

    while (!eof($PKT)) {
    
	last if (read(PKT, $buf, 14) != 14);
	
	($PKTver, $orgnode, $destnode, $orgnet, $destnet, $attrib, $cost) = unpack("SSSSSSS",$buf);

	undef $PKTver;		#  not used for anything yet - 8/26/01 rjc
	undef $attrib;		#  not used for anything yet - 8/26/01 rjc
	undef $cost;		#  not used for anything yet - 12/15/01 rjc 

	$osep = $/;                   
	$/ = "\0";                    

	$datetime = <PKT>;         
	if (length($datetime) > 20) {
             $to = substr($datetime,20);
	} else {
	    $to = <PKT>;
	}
	$from = <PKT>;
	$subj = <PKT>;

	$to   =~ tr/\200-\377/\0-\177/;     # mask hi-bit characters
	$to   =~ tr/\0-\037/\040-\100/;     # mask control characters
	$from =~ tr/\200-\377/\0-\177/;     # mask hi-bit characters
	$from =~ tr/\0-\037/\040-\100/;     # mask control characters
	$subj =~ tr/\0-\037/\040-\100/;     # mask control characters

	$s = <PKT>;      
	$/ = $osep;

	$s =~ s/\x8d/\r/g;    
	@lines = split(/\r/,$s);  

	undef $s;     

	next if ($#lines < 0);      

	$area = shift(@lines);          
	$_ = $area;
	$area ="NETMAIL" if /\//i;		# default netmail area name
	$area =~ s/.*://;			# strip "area:"
	$area =~ tr/a-z/A-Z/;			# Force upper case ???
          
	@kludges = ();

	for ($i = $k = 0; $i <= $#lines; $i++) {
	    
	    if ($lines[$i] =~ /^\001/) {       
		$kludges[$k++] = splice(@lines,$i,1);
		redo;
	    }
	}
          
	for (;;) {
	    $_ = pop(@lines);
	    last if ($_ eq "");  
	    if (/ \* origin: /i) {
		$origin = substr($_,11);
		last;
	    }
	    if (/---/) {
		$mailer = $_;
	    }
	    if (/seen-by/i) {
		$seenby=$_;
	    }
	}
      
	if ( ! $mailer ) {
	    $mailer = "---";
	}

	if ($#lines < 0) {
	    @lines = ("[empty message]");
	}
    
	# get message body
	$msgbody = "";	#  ensure that it starts empty

	foreach $s (@lines) {
	    $s =~ tr/\0-\037/\040-\100/;   
	    $s =~ s/\s+$//;                
	    $s=~tr/^\*/ /;
	    $msgbody .= "$s\n"; 
	}

	$msgbody .= "$mailer\n" if ($mailer);
	$msgbody .= " * Origin: $origin\n" if ($origin);

	# get control info
	my $ctrlinfo = "";	#  ensure that it starts empty 
	$ctrlinfo .= "$seenby\n" if ($seenby);
	foreach $s (@kludges) {
	    $s =~ s/^\001//;
	    
	    # If kludge starts with "MSGID:", stick that in a special 
	    # variable. 
	    if ( substr($s, 0, 6) eq "MSGID:" ) { 
		$msgid = substr($s, 7);
	    }
	    
	    $ctrlinfo .= "$s\n";
	}

	if ( ! $msgid) {
	    $msged = "msged id not available";
	}

	# get replyid from kludges? same way as get seenby?
	$replyid = "reply id not available";
            
	$fromnode =  "1:$orgnet/$orgnode\n";	# need to pull zone num's from
	$tonode = "1:$destnet/$destnode\n";	# pkt instead of defaulting 1 
    
	my %msg_info = (

	    area => $area,
    
	    ftscdate => $datetime,

	    # removed this: $tz\n";  		# not useing this yet

	    #undef $cost;			# not useing this yet...
	    fromnode => $fromnode,
	    tonode => $tonode,

	    from => $from,
	    to => $to,
	    subj => $subj,

	    msgid => $msgid,    
	    replyid => $replyid,  

	    body => $msgbody,

	    ctrlinfo => $ctrlinfo

	);
    
	push(@messages, \%msg_info);
     

    }   # end while
    
    return (\@messages);
    
}   # end sub read_ftn_packet


=head2 write_ftn_packet

Syntax:  write_ftn_packet($OutDir, \%PktInfo, \@messages);

Create a Fidonet/FTN packet, where:
    $OutDir is the directory where the packet is to be created
    \%PktInfo is a reference to a hash containing the packet header
    \@messages is reference to an array of references to hashes containing the messages.

=cut

sub write_ftn_packet {

    my ($OutDir,$PktInfo, $messages) = @_;

    my ($PktFile, @lines, $serialno, $buf, $i, $k, $msg_ref);

    my $EOL = "\n\r";
    
    # This part is a definition of the PKT format per FTS-0001

    # PKT Header; initialized variable are constants; last comments are
    #             in pack() notation

    # ${$PktInfo}{OrgNode}				# S
    # ${$PktInfo}{DestNode}			# S
    my ($Year, $Mon, $Day, $Hour, $Min, $Sec);	# SSSSSS	
    my $Baud = 0;				# S
    my $PktVer = 2;				# S   Type 2 packet
    # ${$PktInfo}{OrgNet}				# S
    # ${$PktInfo}{DestNet}				# S
    my $ProdCode = 0x100;			# S   product code: ?
    # ${$PktInfo}{PassWord}			# a8
    # ${$PktInfo}{OrgZone}				# S
    # ${$PktInfo}{DestZone}			# S
    my $AuxNet = ${$PktInfo}{OrgNet};		# S
    my $CapWord = 0x100;			# S   capability word: Type 2+
    my $ProdCode2 = 0;				# S   ?
    my $CapWord2 = 1;				# S   byte swapped cap. word
    # ${$PktInfo}{OrgZone}				# S   (repeat)
    # ${$PktInfo}{DestZone}			# S   (repeat)
    # ${$PktInfo}{OrgPoint}			# S
    #  config file for node info?
    # ${$PktInfo}{DestPoint}			# S
    my $ProdSpec = 0;				# L   ?

    # MSG Header; duplicated variables are shown as comments to indicate
    #             the MSG Header structure

    # $PktVer				# S   (repeat)
    # ${$PktInfo}{OrgNode}			# S   (repeat)
    # ${$PktInfo}{DestNode}		# S   (repeat)
    # ${$PktInfo}{OrgNet}			# S   (repeat)
    # ${$PktInfo}{DestNet}			# S   (repeat)
    my $Attrib = 0;			# S
    my $Cost = 0;			# S
    # ${$msg_ref}{DateTime}		# a20 (this is a local())
    # ${$msg_ref}{To}			# a? (36 max)
    # ${$msg_ref}{From}			# a? (36 max)
    # ${$msg_ref}{Subj}			# a? (72 max)

    #"AREA: "                           # c6          }
    # ${$PktInfo}{Area}			# a? (max?)   } all this is actually part
    #possible kludges go here. 0x01<TAG>0x0D          } of the TEXT postions
    #TEXT goes here. (ends with 2 0x0D's ???)         }

    # ${$PktInfo}{TearLine}
    my $Origin = " * Origin: ${$PktInfo}{Origin}  (${$PktInfo}{OrgZone}:${$PktInfo}{OrgNet}/${$PktInfo}{OrgNode}.1)$EOL";
    my $SeenBy = "SEEN-BY: ${$PktInfo}{OrgNet}/${$PktInfo}{OrgNode}$EOL";
    my $Path = "\1PATH: ${$PktInfo}{OrgNet}/${$PktInfo}{OrgNode}$EOL\0";          # note the \0 in $Path

    # repeat MSG Headers/TEXT

    # null (S) to mark done

    my $nmsgs = 0;

    # this is where a loop would go if more than one feed

    # PKT name as per FTS
    ($Sec, $Min, $Hour, $Day, $Mon, $Year) = localtime();
    $Year += 2000;
    #  does the above actually give a two digit year? 
    #			the original above was 1900 instead of 1900
    $PktFile = sprintf("%s/%02d%02d%02d%02d.PKT",$OutDir,$Day,$Hour,$Min,$Sec);

    open(PKT,">$PktFile") || die;

    binmode(PKT);

    #	write packet header
    $buf = pack("SSSSSSSSSSSSSa8SSSSSSSSSSL",
               ${$PktInfo}{OrgNode}, ${$PktInfo}{DestNode},
               $Year, $Mon, $Day, $Hour, $Min, $Sec,
               $Baud, $PktVer,
               ${$PktInfo}{OrgNet}, ${$PktInfo}{DestNet},
               $ProdCode, ${$PktInfo}{PassWord},
               ${$PktInfo}{OrgZone}, ${$PktInfo}{DestZone}, $AuxNet,
               $CapWord, $ProdCode2, $CapWord2,
               ${$PktInfo}{OrgZone}, ${$PktInfo}{DestZone},
               ${$PktInfo}{OrgPoint}, ${$PktInfo}{DestPoint}, $ProdSpec);
    syswrite(PKT,$buf,58);

    # needs to iterate over the array of hashes representing the messages
    foreach $msg_ref ( @{$messages} ) {
    #while ( @{$messages} > 0) {
    #while ( @{$messages} ) {

	#$msg_ref = pop(@{$messages});			# get next message hash reference
         
	# get text body, translate LFs to CRs
         
	@lines = ${$msg_ref}{Body};
	grep(s/\n/\r/,@lines);
         
	# kill leading blank lines
         
	shift(@lines) while ($lines[0] eq "\n");
                  
	++$nmsgs;                           # informative only
         
	# write message to PKT file
         
	# Write Message Header	    
	$buf = pack("SSSSSSSa20",
		$PktVer,${$PktInfo}{OrgNode},${$PktInfo}{DestNode},${$PktInfo}{OrgNet},
		${$PktInfo}{DestNet},$Attrib,$Cost,${$msg_ref}{DateTime});
	print PKT $buf;

	print PKT "${$msg_ref}{To}\0";
	print PKT "${$msg_ref}{From}\0";
	print PKT "${$msg_ref}{Subj}\0";
	print PKT "AREA: ${$PktInfo}{Area}$EOL";         # note: CR not nul
         
	$serialno = unpack("%16C*",join('',@lines));
	$serialno = sprintf("%lx",$serialno + time);
	print PKT "\1MSGID: ${$PktInfo}{OrgZone}:${$PktInfo}{OrgNet}/${$PktInfo}{OrgNode}.${$PktInfo}{OrgPoint} $serialno$EOL";
         
	print PKT @lines; 
	print PKT $EOL,${$PktInfo}{TearLine},$Origin,$SeenBy,$Path;
         
	@lines = ();                        # all done with array (frees mem?)
          
    }
    
    print PKT "\0\0";                      # indicates no more messages

    close(PKT);

    return 0;
}

__END__ 

=head1 EXAMPLES

  use FTN:Packet;
  To be added...

=head1 AUTHORS

Robert James Clay, jame@users.sf.net

=head1 ACKNOWLEDGEMENTS

Code for the read_ftn_packet function was initially derived from the newmsgs subroutine
in the set of scripts for reading FTN packets (pkt2txt.pl, pkt2xml.pl, etc) by
Russ Johnson L<airneil@users.sf.net> and Robert James Clay L<jame@users.sf.net>
available at the L<http://ftnpl.sourceforge.net>] project site. Initial code for
the write_ftn_packet function was derived from the bbs2pkt.pl of v0.1 of the bbsdbpl
scripts, also at the SourceForge project.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc FTN::Packet

=head1 SEE ALSO

 L<perl(1)>

=head1 COPYRIGHT & LICENSE

Copyright 2001-2004,2006 Robert James Clay, all rights reserved.
Copyright 2001-2003 Russ Johnson, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;

