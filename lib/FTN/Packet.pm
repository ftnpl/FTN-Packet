package FTN::Packet;

use strict;
use warnings;

=head1 NAME

FTN::Packet - Reading or writing Fidonet Technology Networks (FTN) packets.

=head1 VERSION

VERSION 0.11

=cut

our $VERSION = '0.11';

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
@EXPORT_OK = qw( &read_ftn_packet &write_ftn_packet
);

=head1 FUNCTIONS

=head2 read_ftn_packet

Syntax:  $messages = read_ftn_packet(*PKT);

Read a Fidonet/FTN packet.  Returns the messages in the packet as a reference
to an array of hash references, which can be read as follows:

    $message_ref = pop(@{$messages});
    $msg_area = ${$message_ref}->('area');
    $msg_date = ${$message_ref}->('ftscdate');
    $msg_tonode = ${$message_ref}->('tonode');
    $msg_from = ${$message_ref}->('from');
    $msg_body = ${$message_ref}->('to');
    $msg_subj = ${$message_ref}->('subj');
    $msg_msgid = ${$message_ref}->('msgid');
    $msg_replyid = ${$message_ref}->('replyid');
    $msg_body = ${$message_ref}->('body');
    $msg_ctrl = ${$message_ref}->('ctrlinfo');

=cut

###############################################
# Read Messages from FTN packet 
###############################################
sub read_ftn_packet {

    my ($PKT) = @_;
    # "$PKT" is a file pointer to the packet file being read
    # Returns an array of hash references

    my ($packet_version,$origin_node,$destination_node,$origin_net,$destination_net,$attribute,$cost,$buffer);
    my ($separator, $s, $date_time, $to, $from, $subject, $area, @lines, @kludges,
        $from_node, $to_node, @messages, $message_body, $message_id, $reply_id, $origin,
        $mailer, $seen_by, $i, $k);

    # Ignore packet header
    read($PKT,$buffer,58);

    while (!eof($PKT)) {

        last if (read($PKT, $buffer, 14) != 14);

        ($packet_version, $origin_node, $destination_node, $origin_net, $destination_net, $attribute, $cost) = unpack("SSSSSSS",$buffer);

        #  not used for anything yet - 8/26/01 rjc
        undef $packet_version;

        #  not used for anything yet - 8/26/01 rjc
        undef $attribute;

        #  not used for anything yet - 12/15/01 rjc 
        undef $cost;

        $separator = $/;
        local $/ = "\0";

        $date_time = <$PKT>;
        if (length($date_time) > 20) {
             $to = substr($date_time,20);
        } else {
            $to = <$PKT>;
        }
        $from = <$PKT>;
        $subject = <$PKT>;

        $to   =~ tr/\200-\377/\0-\177/;     # mask hi-bit characters
        $to   =~ tr/\0-\037/\040-\100/;     # mask control characters
        $from =~ tr/\200-\377/\0-\177/;     # mask hi-bit characters
        $from =~ tr/\0-\037/\040-\100/;     # mask control characters
        $subject =~ tr/\0-\037/\040-\100/;     # mask control characters

        $s = <$PKT>;
        local $/ = $separator;

        $s =~ s/\x8d/\r/g;
        @lines = split(/\r/,$s);

        undef $s;

        next if ($#lines < 0);

        $area = shift(@lines);
        $_ = $area;

        # default netmail area name
        $area ="NETMAIL" if /\//i;

        # strip "area:"
        $area =~ s/.*://;

        # Force upper case ???
        $area =~ tr/a-z/A-Z/;	

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
                $seen_by=$_;
            }
        }

        if ( ! $mailer ) {
            $mailer = "---";
        }

        if ($#lines < 0) {
            @lines = ("[empty message]");
        }

        # get message body
        $message_body = "";	#  ensure that it starts empty

        foreach my $s (@lines) {
            $s =~ tr/\0-\037/\040-\100/;
            $s =~ s/\s+$//;
            $s=~tr/^\*/ /;
            $message_body .= "$s\n";
        }

        $message_body .= "$mailer\n" if ($mailer);
        $message_body .= " * Origin: $origin\n" if ($origin);

        # get control info
        my $control_info = "";	#  ensure that it starts empty 
        $control_info .= "$seen_by\n" if ($seen_by);
        foreach my $c (@kludges) {
            $c =~ s/^\001//;

            # If kludge starts with "MSGID:", stick that in a special 
            # variable. 
            if ( substr($c, 0, 6) eq "MSGID:" ) {
                $message_id = substr($c, 7);
            }

            $control_info .= "$s\n";
        }

        if ( ! $message_id) {
            $message_id = "message id not available";
        }

        # get replyid from kludges? same way as get seenby?
        $reply_id = "reply id not available";

        # need to pull zone num's from pkt instead of defaulting 1 
        $from_node =  "1:$origin_net/$origin_node\n";
        $to_node = "1:$destination_net/$destination_node\n";

        my %message_info = (

            area => $area,

            ftscdate => $date_time,

            ## not useing this yet...
            #cost => $cost,

            fromnode => $from_node,
            tonode => $to_node,

            from => $from,
            to => $to,
            subj => $subject,

            msgid => $message_id,    
            replyid => $reply_id,  

            body => $message_body,

            ctrlinfo => $control_info

            );

            push(@messages, \%message_info);

    }   # end while

    return \@messages;

}   # end sub read_ftn_packet


=head2 write_ftn_packet

Syntax:  write_ftn_packet($OutDir, \%packet_info, \@messages);

Create a Fidonet/FTN packet, where:
    $OutDir is the directory where the packet is to be created
    \%packet_info is a reference to a hash containing the packet header
    \@messages is reference to an array of references to hashes containing the messages.

=cut

sub write_ftn_packet {

    my ($OutDir, $packet_info, $messages) = @_;

    my ($packet_file, $PKT, @lines, $serialno, $buffer, $nmsgs, $i, $k, $message_ref);

    my $EOL = "\n\r";

    # This part is a definition of an FTN Packet format per FTS-0001

    # PKT Header; initialized variable are constants; last comments are
    #             in pack() notation

    # ${$packet_info}{OrgNode}                              # S
    # ${$packet_info}{DestNode}                             # S
    my ($year, $month, $day, $hour, $minutes, $seconds);    # SSSSSS
    my $Baud = 0;                                           # S
    my $packet_version = 2;                                 # S   Type 2 packet
    # ${$packet_info}{OrgNet}                               # S
    # ${$packet_info}{DestNet}                              # S
    my $ProdCode = 0x100;                                   # S   product code: ?
    # ${$packet_info}{PassWord}                             # a8
    # ${$packet_info}{OrgZone}                              # S
    # ${$packet_info}{DestZone}                             # S
    my $AuxNet = ${$packet_info}{OrgNet};                   # S
    my $CapWord = 0x100;                                    # S   capability word: Type 2+
    my $ProdCode2 = 0;                                      # S   ?
    my $CapWord2 = 1;                                       # S   byte swapped cap. word
    # ${$packet_info}{OrgZone}                              # S   (repeat)
    # ${$packet_info}{DestZone}                             # S   (repeat)
    # ${$packet_info}{OrgPoint}                             # S
    #  config file for node info?
    # ${$packet_info}{DestPoint}                            # S
    my $ProdSpec = 0;                                       # L   ?

    # MSG Header; duplicated variables are shown as comments to indicate
    #             the MSG Header structure

    # $packet_version                                   # S   (repeat)
    # ${$packet_info}{OrgNode}                          # S   (repeat)
    # ${$packet_info}{DestNode}                         # S   (repeat)
    # ${$packet_info}{OrgNet}                           # S   (repeat)
    # ${$packet_info}{DestNet}                          # S   (repeat)
    my $attribute = 0;                                  # S
    my $Cost = 0;                                       # S
    # ${$message_ref}{DateTime}                         # a20 (this is a local())
    # ${$message_ref}{To}                               # a? (36 max)
    # ${$message_ref}{From}                             # a? (36 max)
    # ${$message_ref}{Subj}                             # a? (72 max)

    #"AREA: "                                           # c6          }
    # ${$packet_info}{Area}                             # a? (max?)   } all this is actually part
    #possible kludges go here. 0x01<TAG>0x0D            } of the TEXT postions
    #TEXT goes here. (ends with 2 0x0D's ???)           }

    # ${$packet_info}{TearLine}
    my $Origin = " * Origin: ${$packet_info}{Origin}  (${$packet_info}{OrgZone}:${$packet_info}{OrgNet}/${$packet_info}{OrgNode}.1)$EOL";
    my $seen_by = "SEEN-BY: ${$packet_info}{OrgNet}/${$packet_info}{OrgNode}$EOL";
    my $Path = "\1PATH: ${$packet_info}{OrgNet}/${$packet_info}{OrgNode}$EOL\0";          # note the \0 in $Path

    # repeat MSG Headers/TEXT

    # null (S) to mark done

    # this is where a loop would go if more than one feed

    # PKT name as per FTS
    ($seconds, $minutes, $hour, $day, $month, $year) = localtime();
    $year += 1900;
    #  does the above actually give a two digit year? 
    #			the original above was 1900 instead of 2000
    $packet_file = sprintf("%s/%02d%02d%02d%02d.pkt",$OutDir,$day,$hour,$minutes,$seconds);

    open( $PKT, q{>}, "$packet_file" ) || die;

    binmode($PKT);

    #	write packet header
    $buffer = pack("SSSSSSSSSSSSSa8SSSSSSSSSSL",
               ${$packet_info}{OrgNode}, ${$packet_info}{DestNode},
               $year, $month, $day, $hour, $minutes, $seconds,
               $Baud, $packet_version,
               ${$packet_info}{OrgNet}, ${$packet_info}{DestNet},
               $ProdCode, ${$packet_info}{PassWord},
               ${$packet_info}{OrgZone}, ${$packet_info}{DestZone}, $AuxNet,
               $CapWord, $ProdCode2, $CapWord2,
               ${$packet_info}{OrgZone}, ${$packet_info}{DestZone},
               ${$packet_info}{OrgPoint}, ${$packet_info}{DestPoint}, $ProdSpec);
    syswrite($PKT,$buffer,58);

    # needs to iterate over the array of hashes representing the messages
    foreach my $message_ref ( @{$messages} ) {
    #while ( @{$messages} > 0) {
    #while ( @{$messages} ) {

        ## get next message hash reference
        #$message_ref = pop(@{$messages});

        # get text body, translate LFs to CRs

        @lines = ${$message_ref}{Body};
        grep(s/\n/\r/,@lines);

        # kill leading blank lines

        shift(@lines) while ($lines[0] eq "\n");

        # informative only
        ++$nmsgs;

        # write message to $PKT file

        # Write Message Header	
        $buffer = pack("SSSSSSSa20",
                $packet_version,${$packet_info}{OrgNode},${$packet_info}{DestNode},${$packet_info}{OrgNet},
                ${$packet_info}{DestNet},$attribute,$Cost,${$message_ref}{DateTime});
        print $PKT $buffer;

        print $PKT "${$message_ref}{To}\0";
        print $PKT "${$message_ref}{From}\0";
        print $PKT "${$message_ref}{Subj}\0";
        print $PKT "AREA: ${$packet_info}{Area}$EOL";         # note: CR not nul

        $serialno = unpack("%16C*",join('',@lines));
        $serialno = sprintf("%lx",$serialno + time);
        print $PKT "\1MSGID: ${$packet_info}{OrgZone}:${$packet_info}{OrgNet}/${$packet_info}{OrgNode}.${$packet_info}{OrgPoint} $serialno$EOL";

        print $PKT @lines; 
        print $PKT $EOL,${$packet_info}{TearLine},$Origin,$seen_by,$Path;

        # all done with array (frees mem?)
        @lines = ();

    }

    # indicates no more messages
    print $PKT "\0\0";

    close($PKT);

    return 0;
}

__END__

=head1 EXAMPLES

  use FTN:Packet;
  To be added...

=head1 AUTHORS

Robert James Clay, jame@rocasa.us

=head1 ACKNOWLEDGEMENTS

Code for the read_ftn_packet function was initially derived from the newmsgs subroutine
in the set of scripts for reading FTN packets (pkt2txt.pl, pkt2xml.pl, etc) by
Russ Johnson L<mailto:airneil@users.sf.net> and Robert James Clay L<mailto:jame@rocasa.us>
available at the L<http://ftnpl.sourceforge.net>] project site. Initial code for
the write_ftn_packet function was derived from the bbs2pkt.pl of v0.1 of the bbsdbpl
scripts, also at the SourceForge project.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc FTN::Packet

=head1 SEE ALSO

 L<perl(1)>

=head1 COPYRIGHT & LICENSE

Copyright 2001-2010 Robert James Clay, all rights reserved.
Copyright 2001-2003 Russ Johnson, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
