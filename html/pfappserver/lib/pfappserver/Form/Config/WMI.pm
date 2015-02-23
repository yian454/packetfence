package pfappserver::Form::Config::WMI;

=head1 NAME

pfappserver::Form::Config::WMI - Web form for a WMI

=head1 DESCRIPTION

Form definition to create or update WMI.

=cut

use HTML::FormHandler::Moose;
extends 'pfappserver::Base::Form';
with 'pfappserver::Base::Form::Role::Help';

use pf::config;
use pf::util;

## Definition
has_field 'id' =>
  (
   type => 'Text',
   label => 'Name',
   required => 1,
   messages => { required => 'Please specify a name for the scan engine' },
  );

has_field 'request' =>
  (
   type => 'Text',
   label => 'Request',
   required => 1,
   messages => { required => 'Please specify a Request' },
  );


has_field 'action' =>
  (
   type => 'TextArea',
   label => 'Rules Actions',
   required => 1,
   tags => { after_element => \&help,
             help => 'Add the action based on the result of the request' },
  );

has_block definition =>
  (
   render_list => [ qw(request action) ],
  );

=over

=back

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

__PACKAGE__->meta->make_immutable;
1;
