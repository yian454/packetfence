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
