#!/usr/bin/perl
=head1 NAME

add_ldap_entry.pl add documentation

=cut

=head1 DESCRIPTION

add_ldap_entry.pl

=head1 SYNOPSIS

add_ldap_entry.pl [OPTIONS]

Options:

  --server=SERVER                       Required: The ldap server accepts either the server name or an ldap uri
                                        ldapserver.domain.tld, ldaps://127.0.0.1:636, ldap://127.0.0.1:389
  --user=USER                           The full distinguished name for the user ex "CN=tests,DC=inverse,DC=local"
  --password=PASSWORD                   Optional: The password for the user. This option or passwordfile must be set
  --password-file=PASSWORDFILE          Optional: A file that contains the user password. This option or password must be set
  --object-class OBJECT [OBJECT ...]    Optional: The list of the objectclass for the entry. Default: top person user organizationalPerson
                                          ex: --object-class top person user organizationalPerson
  --cn=COMMONNAME                       Required: The common name of the entry
  --ou=OU                               Required: The Organizational Unit
  --attribute NAME VALUE                Optional: Additional attribute to add to the entry can be called multiple times
                                          ex: --attribute name1 value1 --attribute name2 value2
  --help                                Will show this

=cut

use strict;
use warnings;
use Net::LDAP;
use Net::LDAP::Util qw(escape_dn_value);
use File::Slurp;
use Getopt::Long;
use Pod::Usage qw(pod2usage);
use List::MoreUtils qw(notall);

my ($user,$passwordfile,$password,$server,$cn,$ou,$help);
my @object_class = (qw(top person user organizationalPerson));
my @attributes;

GetOptions (
    "user=s" => \$user,    # numeric
    "server=s" => \$server,
    "password=s"   => sub {$passwordfile = undef;$password=$_[1]; },      # string
    "password-file=s"   => sub {$passwordfile = $_[1];$password=undef; },      # string
    "object-class=s{1,}" => \@object_class,
    "cn=s" => \$cn,
    "ou=s" => \$ou,
    "attribute=s{2}" => \@attributes,
    "help|h" => \$help,
) || die pod2usage(2);

if($help) {
    pod2usage(0);
}

chomp ($password = read_file($passwordfile)) if $passwordfile;

if( notall {defined $_ }  ($user, $password, $server, $cn, $ou)    ) {
    die pod2usage("The following options be passed:  user, server, cn, ou and either password or passwordfile");
}

$cn = escape_dn_value($cn);

my $ldap = Net::LDAP->new ( $server ) || die "cannot create an ldap object\n";
my $result = $ldap->bind (
    $user , password => $password,
    version => 3 )  || die "cannot bind to $server \n";

my @attrs = (
   objectClass => \@object_class,
   cn => $cn,
   @attributes
#   macAddress => '00:01:02:03:04:06'
 );

my $dn = "cn=$cn,$ou";
$result = $ldap->add ( $dn, attrs => \@attrs );
if($result->is_error) {
    print STDERR "Cannot add new entry $dn\n";
    print STDERR "Error: ",$result->error,"\n";
    exit 1;
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

Minor parts of this file may have been contributed. See CREDITS.

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

