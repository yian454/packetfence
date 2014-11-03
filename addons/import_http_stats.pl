#!/usr/bin/perl
=head1 NAME

import_http_stats.pl - Import HTTP stats request

=head1 DESCRIPTION

=head1 EXAMPLE

./import_http_stats.pl -file=/root/file.csv

=cut

require 5.8.5;
use strict;
use warnings;

use FindBin;
use Getopt::Long;
use Pod::Usage;
use Text::CSV;

use constant {
    LIB_DIR   => $FindBin::Bin . "/../lib",
};

use lib LIB_DIR;

use pf::stats;
use Digest::MD5;

my $filename;

GetOptions(
    "file:s" => \$filename,
) ;

if (! defined($filename)) {
    print "The 'file' argument must be specified\n";
    exit 0;
}

if (!(-e $filename)) {
    print "File $filename does not exists !\n";
    exit 0;
}

my $csv = Text::CSV->new({ binary => 1 , sep_char => ';'});
open my $io, "<", $filename
    or die("Unable to import from file: $filename. Error: $!");

my $stats = pf::stats->new();
my $md5 = Digest::MD5->new;

while (my $row = $csv->getline($io)) {

    my ($mac,$ua,$uaprof,$suites) = @$row;

    $md5->add($mac,$ua,$uaprof,$suites);
    $stats->stats_http($mac,$md5->hexdigest,$ua,$uaprof,$suites);
}

print "End of node bulk importation\n";
close $io;

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2014 Inverse inc.

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

# vim: set shiftwidth=4:
# vim: set expandtab:
# vim: set backspace=indent,eol,start:
