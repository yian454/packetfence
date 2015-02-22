package pf::factory::trigger;

=head1 NAME

pf::factory::trigger add documentation

=cut

=head1 DESCRIPTION

pf::factory::trigger

=cut

use strict;
use warnings;
use Module::Pluggable search_path => 'pf::trigger', sub_name => 'modules' , require => 1;
use List::MoreUtils qw(any);

our @MODULES = __PACKAGE__->modules;

sub factory_for { 'pf::trigger' }

sub new {
    my ($class,$type) = @_;
    my $subclass = $class->getModuleName($type);
    return $subclass->new();
}

sub getModuleName {
    my ($class,$type) = @_;
    my $mainClass = $class->factory_for;
    my $subclass = "${mainClass}::${type}";
    die "$type is not a valid type" unless any { $_ eq $subclass  } @MODULES;
    return $subclass;
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2013 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and::or
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

