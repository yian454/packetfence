package pf::flow;

=head1 NAME

pf::flow - Module that deals with everything netflow/IPFIX related

=head1 SYNOPSIS

The pf::flow module contains the functions necessary for flow processing.

All the behavior contained here can be overridden in lib/pf/flow/custom.pm.

=cut

use strict;
use warnings;
use diagnostics;

use Log::Log4perl;

#TODO not sure about these yet
#use pf::config;
#use pf::util;

our $TemplateArrayRef = undef;
our $templateReceivedFlag = 0;
our $info_string = "Size\t#pkts\tsrcip\t\tsrcport\tdstip\t\tdstport\tsrcmac\t\t\tdstmac\t\t\tnexthop";

=head1 SUBROUTINES

=over

=cut

=item * new - get a new instance of the flow object
 
=cut
sub new {
    my $logger = Log::Log4perl::get_logger("pf::flow");
    $logger->debug("instantiating new pf::flow object");
    my ( $class, %argv ) = @_;
    my $this = bless {}, $class;
    return $this;
}

=item processFlowPacket

parses a flow packet and decompose it in several streams

=cut
sub processFlowPacket {
    my ($this, $packet) = @_; 
    my $logger = Log::Log4perl->get_logger("pf::flow");

    my ($HeaderHashRef,$FlowArrayRef,$ErrorsArrayRef);
    ($HeaderHashRef, $TemplateArrayRef, $FlowArrayRef, $ErrorsArrayRef) = Net::Flow::decode($packet, $TemplateArrayRef);

    # TODO: ERROR-HANDLING of Net::Flow
    if (@{$ErrorsArrayRef}) {
        foreach my $error (@{$ErrorsArrayRef}) {
            if ($error =~ /^WARNING/) {
                $logger->trace("got a warning from Net::Flow::decode. Usually normal: $error.");
            } else {
                $logger->warn("Net::Flow::decode error: $error.");
            }
        }
    }

    if (!$templateReceivedFlag && @{$TemplateArrayRef}) {
        $logger->info("Received the template. Flows are now interpreted.");
        $templateReceivedFlag = 1;
    }

    if (!@{$TemplateArrayRef}) {
        $logger->debug("No template received yet. Can't parse the netflow/IPFIX until a template has been received");
    } 

    if (@{$FlowArrayRef}) {
        $logger->trace($info_string);
    }

    foreach my $FlowRef ( @{$FlowArrayRef} ){

        # all time is epoch
        # startdate: int($FlowRef->{22}/1000) + $HeaderHashRef->{"UnixSecs"} #warn: int is not rounding precisely
        # enddate: int($FlowRef->{21}/1000) + $HeaderHashRef->{"UnixSecs"} #warn: int is not rounding precisely
        my $start_time = hex(unpack("H*", $FlowRef->{22}));
        my $end_time = hex(unpack("H*", $FlowRef->{21}));
        my $numberOfPackets = hex(unpack("H*", $FlowRef->{10}));
     
        my $nexthop = join('.', unpack('CCCC', $FlowRef->{15}));
     
        if($numberOfPackets ne "0") {
            my $data;
            $start_time += $HeaderHashRef->{"UnixSecs"} * 1000;
            $end_time += $HeaderHashRef->{"UnixSecs"} * 1000;
       
            #$data = "FLOW $start_time $end_time ";
            $data = hex(unpack("H*",$FlowRef->{1})) . "\t";                                # Size of Flow
            $data = $data . $numberOfPackets . "\t";                                       # Number of packets
            $data = $data . $this->getSourceIP($FlowRef) . "\t";                           # Source Address
            $data = $data . hex(unpack("H*",$FlowRef->{7})) . "\t";                        # Source Port
            $data = $data . $this->getDestIP($FlowRef) . "\t";                             # Destination Address
            $data = $data . hex(unpack("H*",$FlowRef->{11})) . "\t";                       # Destination Port
            $data = $data . join(':', unpack('H2 H2 H2 H2 H2 H2', $FlowRef->{56})) . "\t"; # Source MAC Address
            $data = $data . join(':', unpack('H2 H2 H2 H2 H2 H2', $FlowRef->{57})) . "\t"; # Destination MAC Address
            $data = $data . join('.', unpack('CCCC',$FlowRef->{15}));                      # Next Hop Address
       
            $logger->trace($data);

            # TODO: so far flows are always oriented the right way (there's a task in TODO to validate that)
            # so src MAC is what we are looking to monitor

            # provide an external hook to discard flows here
            # for ex: if src or dst mac is 802.1X, it's ok

            # identify correct source MAC (direction of the flow)

            # identify node category

            # match all flow rules based on category and apply them
        } else {
            $logger->error("number of packets is ZEROOO!! <------------------------------------");
        }
    }
}

# information about what is in flows in RFC3954 (see references)
sub getSourceIP {
    my ($this, $flowRef) = @_;
    return(join('.', unpack('CCCC', $flowRef->{8})));
}

sub getDestIP {
    my ($this, $flowRef) = @_;
    return(join('.', unpack('CCCC', $flowRef->{12})));
}

sub getSourcePort {
    my ($this, $flowRef) = @_;
    return(hex(unpack("H*", $flowRef->{7})));
}

sub getDestPort {
    my ($this, $flowRef) = @_;
    return(hex(unpack("H*", $flowRef->{11})));
}

sub getSourceMAC {
    my ($this, $flowRef) = @_;
    return(join(':', unpack('H2 H2 H2 H2 H2 H2', $flowRef->{56})));
}

sub getDestMAC {
    my ($this, $flowRef) = @_;
    return(join(':', unpack('H2 H2 H2 H2 H2 H2', $flowRef->{57})));
}


# I am not using these so far
# Number Of Packets: hex(unpack("H*", $FlowRef->{10}));
# Size of flow: hex(unpack("H*",$FlowRef->{1}));
# Next Hop Address: join('.', unpack('CCCC',$FlowRef->{15}));

=back

=head1 BUGS AND LIMITATIONS

It's a feature preview

=head1 REFERENCES

=over

=item RFC3954 - Cisco Systems NetFlow Services Export Version 9

http://www.ietf.org/rfc/rfc3954.txt

=back

=head1 AUTHOR

Olivier Bilodeau <obilodeau@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2010 Inverse inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
