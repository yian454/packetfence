package pf::stats;

use strict;
use DBI;
use Readonly;

Readonly::Scalar our $DATABASE                => "$var_dir/result.db";

=item new

Constructor.

=cut

sub new {
    my ( $class, @argv ) = @_;
    my $this = bless {}, $class;

    my $database = $argv[0] || $DATABASE;

    if (-e $database) {
        $this->stats_connect($database);
    } else {
        $this->stats_connect($database,1); 
    }
    return $this;
}

sub stats_connect {
    my($this,$database,$create) = @_;

    my $sqlite = DBI->connect(          
        "dbi:SQLite:dbname=$database", 
        "",
        "",
        { RaiseError => 1}
    ) or die $DBI::errstr;
    $this->{'sqlite'} = $sqlite;

    if (defined ($create)) {
        $this->create_tables();
    }
}

sub stats_dns {
    my($this,$mac,$domain) = @_;
    my $sqlite = $this->{'sqlite'};

    my  $sth = $sqlite->prepare( "INSERT OR REPLACE INTO dns(mac,domain) VALUES (?,?)");
    $sth->execute($mac,$domain);
}

sub stats_dhcp {
    my($this,$mac,$finger,$vendor_id,$computer_name,$hash) = @_;
    my $sqlite = $this->{'sqlite'};

    my $sth = $sqlite->prepare( "INSERT OR REPLACE INTO dhcp(hash,mac,finger,vendor_id,computer_name) VALUES (?,?,?,?,?)");
    $sth->execute($hash,$mac,$finger,$vendor_id,$computer_name);
}

sub stats_http {
    my($this,$mac,$hash,$user_agent,$uaprof,$suites) = @_;
    my $sqlite = $this->{'sqlite'};

    my $sth = $sqlite->prepare( "INSERT OR REPLACE INTO http(hash,mac,ua,uaprof,suites) VALUES (?,?,?,?,?)");
    $sth->execute($hash,$mac,$user_agent,$uaprof,$suites);
}


sub stats_disconnect {
    my($this) = @_;
    my $sqlite = $this->{'sqlite'};
    $sqlite->disconnect();
}

sub create_tables {
    my($this) = @_;

    my $sqlite = $this->{'sqlite'};


    $sqlite->do("DROP TABLE IF EXISTS mac");
    $sqlite->do("CREATE TABLE mac (mac TEXT PRIMARY KEY, vendor TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS dhcp");
    $sqlite->do("CREATE TABLE dhcp (hash TEXT PRIMARY KEY, mac TEXT, finger TEXT, vendor_id TEXT, computer_name TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS dns");
    $sqlite->do("CREATE TABLE dns (mac TEXT, domain TEXT)");
    $sqlite->do("DROP TABLE IF EXISTS http");
    $sqlite->do("CREATE TABLE http (hash TEXT PRIMARY KEY, mac TEXT, ua TEXT, uaprof TEXT, suites TEXT)");
    $sqlite->do("VACUUM");
}

sub export_dhcp_fingerprint {
    my ($this,$sql) = @_;

    my $sqlite = $this->{'sqlite'};
    my $sth = $sqlite->prepare($sql);
    
    $sth->execute;

    open FILE, ">>", "dhcp_finger.csv" or die $!;

    my $row;
 
    while ($row = $sth->fetchrow_arrayref()) {
        print FILE join("|",@$row)."\n";
    }

}

1;

