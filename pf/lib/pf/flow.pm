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

# Be careful with these since it won't be inherited by subclasses
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

        # provide an external hook to discard flows here
        # for ex: if src or dst mac is 802.1X, it's ok
        if ($this->shouldDiscardFlow($flowRef, $node_info)) {
            return;
        }

        # match all flow rules based on category and apply them
        # TODO cache node's category or cache rules applicable to the node
        my $netflow_conf = $this->getNetflowConf();
        my @rules = $this->getRulesIdForCategory($netflow_conf, $node_info->{'category'});

        if (@rules) {
            # TODO so far, only whitelist processing
            # I should actually branch into whitelist and blacklist processing at this point
            my $result = $this->matchFlowAgainstRules($flowRef, $netflow_conf, @rules);
            if ($result) {
                $logger->debug("flow matched allowed rule id: $result.");
            } else {
                $logger->warn("flow didn't match any whitelist rule! Reporting as a violation");
            }
        }
    } else {
        # TODO: what should be done about it?
        $logger->warn("Flow about a node unknown to PacketFence! MAC: $srcMac");
    }
}

sub matchFlowAgainstRules {
    my ($this, $flowRef, $netflow_conf, @rules) = @_;

    # assume it doesn't match
    my $matches = 0;
    foreach my $rule_id (@rules) {

        my $srcip_match = $this->ipFilter($this->getSourceIP($flowRef), $netflow_conf->{$rule_id}->{'src_ip'});
        my $srcport_match = $this->portFilter($this->getSourcePort($flowRef), $netflow_conf->{$rule_id}->{'src_port'});
        my $dstip_match = $this->ipFilter($this->getDestIP($flowRef), $netflow_conf->{$rule_id}->{'dst_ip'});
        my $dstport_match = $this->portFilter($this->getDestPort($flowRef), $netflow_conf->{$rule_id}->{'dst_port'});

        if ($srcip_match && $srcport_match && $dstip_match && $dstport_match) {
            $matches = $rule_id;
        }
    }
    return $matches;
}

=sub ipFilter

Tells if IP is listed in filter. Supported expressions are * at the group and at the single digit level.

=cut
sub ipFilter {
    my ($this, $ip, $filter) = @_;

    # TODO regexp pre-compilation could be useful: http://www.stonehenge.com/merlyn/UnixReview/col28.html
    # \Q..\E is to quote regexp characters in $filter so that ie . won't match
    if ($ip =~ /^\Q$filter\E$/x) {
        # full IP match
        return 1;
    } elsif ($filter =~ /^\*$/) {
        # full wildcard match
        return 1;
    } elsif ($filter =~ /\*/) {
        # replace first group wildcard (*.x.x.x) in the filter, we change wildcard to match 1-999
        $filter =~ s'^\*\.'\d{1,3}.';
        # replace last group wildcard (x.x.x.*) in the filter, we change wildcard to match 1-999
        $filter =~ s'\.\*$'.\d{1,3}';
        # there's a group wildcard (x.*.x.x) in the filter, we change wildcard to match 1-999
        $filter =~ s'\.\*\.'.\d{1,3}.'g;
        # there's a single digit wildcard (x.*x.x.x) in the filter, we change wildcard to match single digit
        $filter =~ s'\*'\d'g;
        # quote the .
        $filter =~ s'\.'\.'g;
        if ($ip =~ /^$filter$/) {
            return 1;
        }
    }
    return 0;
}

=sub portFilter

Tells if port is listed in filter. Supported expressions are , * and -.

=cut
sub portFilter {
    my ($this, $port, $filter) = @_;

    # TODO regexp pre-compilation could be useful: http://www.stonehenge.com/merlyn/UnixReview/col28.html
    # \Q..\E is to quote regexp characters in $filter so that ie . won't match
    if ($port =~ /^\Q$filter\E$/x) {
        # full port match
        return 1;
    } elsif ($filter =~ /^\*$/) {
        # full wildcard match
        return 1;
    } elsif ($filter =~ /\b$port\b/) {
        # match port directly into a longer expression but no expansion required yet (no dash)
        # ex: 100 in 22,23,25,100,135 but not in 10,1000,1443 or 1100,1443
        return 1;
    } elsif ($filter =~ /\b(\d+)-(\d+)\b/) {
        # matches xxx-xxx with correct boundaries
        if (($port >= $1) && ($port <= $2)) {
            return 1;
        }
    }
    return 0;
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
        $logger->error("Error reading $configfile: " . join( "\n", @errors ) . "\n");
        return;
    }

    # TODO trim arguments
    # TODO perform validation (in an external sub?)
    # TODO validation: policy whitelist and policy blacklist cannot be mixed under same node category
    # TODO validation: node_category must be present
    # TODO validation: in IPs allow * and any variation of x.x.*.x but not x.x.* (missing group) or x.*x.x.x (subgroup)

    return %netflow_conf;
}

=item getNetflowConf

Simple accessor to encapsulate the way I currently store %netflow_conf

=cut
sub getNetflowConf {
    # provided by pfnetflow's main package, returning a ref to avoid copy
    return \%::netflow_conf;
}

sub getRulesIdForCategory {
    my ($this, $netflow_conf, $category) = @_;
    my $logger = Log::Log4perl->get_logger("pf::flow");
 
    my @matching_rules;
    foreach my $rule_id (keys %{$netflow_conf}) {
        if (lc($netflow_conf->{$rule_id}->{node_category}) eq lc($category)) {
            push(@matching_rules, $rule_id);
        }
    }
    $logger->trace("matched ".scalar(@matching_rules)." rules");
    return @matching_rules;
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
