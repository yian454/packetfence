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
use pf::node;

our $TemplateArrayRef = undef;
our $templateReceivedFlag = 0;

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

    foreach my $flowRef (@{$FlowArrayRef}) {
        $this->parseFlow($flowRef);
    }
}


=item parseFlow

Analyzes one flow

=cut
sub parseFlow {
    my ($this, $flowRef) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");

    $logger->trace($this->flowToString($flowRef));
        
    # TODO: so far flows are always oriented the right way (there's a task in TODO to validate that)
    # so src MAC is what we are looking to monitor

    # TODO naive implementation, caching will need to be involved for any of this to scale
    # for caching, Cache would be interesting (packaged as perl-Cache)
    my $srcMac = $this->getSourceMAC($flowRef);
    my $node_info = node_view($srcMac);
    if (defined($node_info) && ref($node_info) eq 'HASH') {
        $logger->trace("this node is: ".$node_info->{'status'});

        # provide an external hook to discard flows here
        # for ex: if src or dst mac is 802.1X, it's ok
        if ($this->shouldDiscardFlow($flowRef, $node_info)) {
            return;
        }

        # identify node category

        # match all flow rules based on category and apply them
    } else {
        # TODO: what should be done about it?
        $logger->warn("Flow about a node unknown to PacketFence! MAC: $srcMac");
    }
}

=item shouldDiscardFlow

If it returns 1, the flow will be discarded and not processed. Meant to be overridden.

=cut
sub shouldDiscardFlow {
    my ($this, $flowRef, $node_info) = @_;
    return 0;
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

=item flowToString

Convenient little wrapper that will output the flow reference in the form: src ip:port (mac) <-> dst ip:port (mac)

=cut
sub flowToString {
    my ($this, $flowRef) = @_;

    return(
        $this->getSourceIP($flowRef) . ":" . $this->getSourcePort($flowRef)
        . " (" . $this->getSourceMAC($flowRef) . ")"
        . " <-> "
        . $this->getDestIP($flowRef) .":". $this->getDestPort($flowRef)
        . " (". $this->getDestMAC($flowRef) . ")"
    );
}

# I am not using these so far
# Size of flow: hex(unpack("H*",$flowRef->{1}));
# Next Hop Address: join('.', unpack('CCCC',$flowRef->{15}));

# Time-related (all time is epoch or sysUpTime related, not so sure)
# startdate: int($flowRef->{22}/1000) + $HeaderHashRef->{"UnixSecs"} #warn: int is not rounding precisely
# enddate: int($flowRef->{21}/1000) + $HeaderHashRef->{"UnixSecs"} #warn: int is not rounding precisely
# my $start_time = hex(unpack("H*", $flowRef->{22}));
# my $end_time = hex(unpack("H*", $flowRef->{21}));

=item read_netflow_conf

Reads all the rules

=cut
sub read_netflow_conf {
    my ($this, $configfile) = @_;
    my $logger = Log::Log4perl::get_logger('pf::flow');

    my %netflow_conf;
    tie %netflow_conf, 'Config::IniFiles', (-file => $configfile);

    my @errors = @Config::IniFiles::errors;
    if (@errors) {
        $logger->error("Error reading netflow.conf: " . join( "\n", @errors ) . "\n");
        return 0;
    }

    # TODO perform validation (in an external sub?)
    # TODO validation: policy whitelist and policy blacklist cannot be mixed under same node category

    return 1;
}       


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
