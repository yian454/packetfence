package pf::Authentication::Source::VHOSource;

=head1 NAME

pf::Authentication::Source::VHOSource

=head1 DESCRIPTION

=cut

use pf::config qw($TRUE $FALSE);
use pf::Authentication::constants;

use Authen::Radius;

use Moose;
extends 'pf::Authentication::Source::RADIUSSource';

has '+type' => ( default => 'VHO' );

sub mlogit {
    my $message = shift;
    open OUT, ">>/tmp/matt.log";
    print OUT scalar localtime time;
    print OUT " ";
    print OUT $message, "\n";
    close OUT;
}

=head2  authenticate

=cut

sub authenticate {

    my ( $self, $username, $password ) = @_;

    my $logger = Log::Log4perl->get_logger('pf::authentication');

    # internet hack since the radius rules can't be changed, try every realm if not defined.
    # matt joubert

    unless ( $username =~ /\@.*mts.net$/ ) {
        my @realms = ( 'resa.mts.net', 'res1.mts.net', 'resc.mts.net', 'resd.mts.net', 'rese.mts.net', 'bhs.mts.net', 'bhs1.mts.net', 'bhs2.mts.net', 'bhs3.mts.net', 'bhsp.mts.net', 'bslv1.mts.net', 'bslv3.mts.net', 'bslv5.mts.net', 'bgld1.mts.net', 'bgld3.mts.net', 'bgld5.mts.net', 'wifi.mts.net' );

        my $radius = new Authen::Radius(
            Host   => "$self->{'host'}:$self->{'port'}",
            Secret => $self->{'secret'},
        );

        if ( defined $radius ) {
            foreach (@realms) {
                my $username = "$username\@$_";
                my $result = $radius->check_pwd( $username, $password );

                if ( $radius->get_error() eq 'ENONE' ) {

                    if ($result) {
                        $logger->error("Success RADIUS Sneaky Auth on realm $_");
                        return ( $TRUE, 'Successful authentication using RADIUS.' );
                    }
                }
            }
        }

        # mts my accout screen scraping hack
        # matt joubert
        my $ua = LWP::UserAgent->new;
        $ua->cookie_jar( { file => "$ENV{HOME}/.cookies.txt" } );
        $ua->agent("Wi-Fi Authenticator/1.0");
        push @{ $ua->requests_redirectable }, 'POST';
        $ua->env_proxy;
        $ua->get('https://www.mts.ca/mts/myaccount');
        my $post = "action=login&userid=$username&password=$password&rememberme=on&as_fid=m7znkirWJb5WpzJxaT";
        my $req = HTTP::Request->new( POST => 'https://www2.mts.ca/MTSCASSO/sso' );
        $req->content_type('application/x-www-form-urlencoded');
        $req->content($post);

        my $res = $ua->request($req);

        # Check the outcome of the response
        if ( $res->is_success ) {
            my $res      = $ua->get("https://www2.mts.ca/mts/myaccount/account+overview");
            my $buffer   = $res->content;
            my $internet = 0;
            my $wireless = 0;
            my $tv       = 0;

            if ( $buffer =~ /Internet Overview/ ) {
                $internet = 1;
            }

            if ( $buffer =~ /Wireless Overview/ ) {
                $wireless = 1;
            }

            if ( $buffer =~ /(?<!Change My TV Channels and )Access MyPVR/ ) {
                $tv = 1;
            }

            return ( $TRUE, 'Successful authentication using Internet internet.' ) if $internet == 1;
            return ( $TRUE, 'Successful authentication using Wireless internet.' ) if $wireless == 1;
            return ( $TRUE, 'Successful authentication using TV.' )                if $tv == 1;
        }

        $logger->error( "Unable to perform RADIUS authentication on any server: " . Authen::Radius::get_error() );
        return ( $FALSE, 'Unable to authenticate successfully using RADIUS.' );
    }
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2013 Inverse inc.

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

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
