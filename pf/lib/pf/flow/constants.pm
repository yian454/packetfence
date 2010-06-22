package pf::flow::constants;

=head1 NAME

pf::flow::constants - Constants for pf::flow to be consumed by flow modules

=head1 DESCRIPTION

This file is splitted by packages and refering to the constant require you to
specify the package.

This unintuitive way of handling constants is done to circumvent Perl's inhability to inherit variables in class 
hierarchies.

=cut

use strict;
use warnings;
use diagnostics;

use Readonly;

=head1 POLICY

=cut
package POLICY;

=item Policy

Flow rules can follow two different policies: blacklist or whitelist.
In whitelist mode you specify what traffic patterns are allowed and a violation is triggered if a given flow doesn't 
match any of the traffic patterns.
In blacklist mode you specify what traffic patterns are not authorized and a violation is triggered if such a pattern 
is recognized.

=cut
Readonly::Scalar our $WHITELIST => 'whitelist';
Readonly::Scalar our $BLACKLIST => 'blacklist';

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
