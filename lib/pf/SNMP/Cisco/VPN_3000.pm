package pf::SNMP::Cisco::VPN_3000;

=head1 NAME

pf::SNMP::Cisco::VPN_3000

=head1 DESCRIPTION

Object oriented module to handle VPN traffic from VPN Concentrator 3000

=cut
use strict;
use warnings;

use Log::Log4perl;
use Net::SNMP;

use pf::config;

use base ('pf::SNMP::Cisco');

# CAPABILITIES
sub supportsVPN() { return $TRUE; }

sub disconnectVPN() {
    my ($this,$username) = @_;
    
    #Check in the alActiveSessionUserName OIDs for every occurance of a username
    my $logger = Log::Log4perl::get_logger( ref($this) );
    my @oid_value;
    my $oid_alActiveSessionRowStatus = '1.3.6.1.4.1.3076.2.1.2.17.2.1.1';
    my $index = 1;

    if ( !$this->isProductionMode() ) {
        $logger->info(
            "not in production mode ... we won't disconnect the user"
        );
        return 0;
    }

    my $rows = getActiveSessionUsername($username);

    if ( !$this->connectWrite() ) {
        return 0;
    }

    foreach my $oids { keys %{$rows} } (
        if ($rows->{$oids} eq $username) {
            push @oid_value, ($oid_alActiveSessionRowStatus.$index,Net::SNMP::INTEGER, $SNMP::DESTROY);
        }
        $index+=1;
    )
    
    if (@oid_value) {
        logger->trace("SNMP set_request for alActiveSessionRowStatus");
        $result = $this->{_sessionWrite}->set_request(-varbindlist => \@oid_value);
        if (!defined($result)) {
            $logger->warn(
                "SNMP error tyring to disconnect a user session on the VPN concentrator. "
                . "Error message: ".$this->{_sessionWrite}->error()
            );
        }

    } else {
        $logger->info("Cannot find the proper index to disconnect the user, doing nothing");
        return 0;
    }

    return 1;
}

sub getActiveSessionUsername() {
    my ($this,$username) = @_;

    #Check in the alActiveSessionUserName OIDs for every occurance of a username
    my $logger = Log::Log4perl::get_logger( ref($this) );
    my $oid_alActiveSessionUserName = '1.3.6.1.4.1.3076.2.1.2.17.2.1.3';
    my $result = {};

    if ( !$this->isProductionMode() ) {
        $logger->info(
            "not in production mode ... we won't disconnect the user"
        );
        return $result;
    }

    if ( !$this->connectRead() ) {
        return $result;
    }

    $result = $this->{_sessionRead}
            ->get_request( -baseoid => $oid_alActiveSessionUserName );
    
    return $result;
}

=head1 AUTHOR

Olivier Bilodeau <obilodeau@inverse.ca>

Dominik Gehl <dgehl@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2006-2011 Inverse inc.

=head1 LICENSE

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
