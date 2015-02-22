package pfappserver::Form::Config::Fingerbank::Device;

=head1 NAME

pfappserver::Form::Config::Fingerbank::Device - Web form for an admin role

=head1 DESCRIPTION

Form definition to create or update an admin role

=cut

use HTML::FormHandler::Moose;
extends 'pfappserver::Base::Form';
with 'pfappserver::Base::Form::Role::Help';

use pf::admin_roles;
use pf::log;

has roles => ( is => 'rw', default => sub { [] } );

## Definition
has_field 'id' =>
  (
   type => 'Text',
   label => 'Id',
   required => 1,
  );

has_field name =>
  (
   type => 'Text',
   readonly => 1,
  );

has_field [qw(mobile tablet)] =>
  (
   type => 'Toggle',
   readonly => 1,
  );

has_field created_at =>
  (
  type => 'Text',
  readonly => 1,
  );

has_field updated_at =>
  (
  type => 'Text',
  readonly => 1,
  );

has_block definition =>
  (
    render_list => [qw(name mobile tablet created_at updated_at)],
  );

=head1 COPYRIGHT

Copyright (C) 2013 Inverse inc.

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

__PACKAGE__->meta->make_immutable;
1;
