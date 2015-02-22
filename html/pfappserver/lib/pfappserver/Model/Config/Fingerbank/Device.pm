package pfappserver::Model::Config::Fingerbank::Device;

=head1 NAME

pfappserver::Model::Config::Fingerbank::Device

=cut

=head1 DESCRIPTION

pfappserver::Model::Config::Fingerbank::Device

=cut

use fingerbank::Model::Device();
use Moose;
use namespace::autoclean;
use pf::config::cached;
use pf::log;
use HTTP::Status qw(:constants :is);

extends 'pfappserver::Base::Model::Fingerbank';

has '+fingerbankModel' => ( default => 'fingerbank::Model::Device');


__PACKAGE__->meta->make_immutable;

=head1 COPYRIGHT

Copyright (C) 2014 Inverse inc.

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
