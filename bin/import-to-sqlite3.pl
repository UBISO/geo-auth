#!/usr/bin/perl -w
#
# This is to be used with the IP-COUNTRY-REGION-CITY-LATITUDE-LONGITUDE
# datafile available from http://www.ip2location.com
#
# This script will import their CSV file into a sqlite database, with
# a spatial (r-tree) table for fast searching (via a join). 

use strict;
use Text::CSV;
use DBI;

my $f = shift;
die "$0 [csv file]\n" unless $f && -r $f;

my @bootstrap = (
		 qq{DROP TABLE IF EXISTS ip2loc},
 		 qq{DROP TABLE IF EXISTS ip2loc_rtree},


		 qq{create table ip2loc (
                       oct1 integer unsigned not null,
                       oct2 integer unsigned not null,
                       ipstart integer unsigned not null,
                       ipend integer unsigned not null,
                       shortcc char(2),
                       longcc varchar(32),
                       region varchar(64),
                       city varchar(64),
                       latitude float,
                       longitude float
                     )},
		
		 qq{create index ip2locidx1 on ip2loc(ipstart)},
		 qq{create index ip2locidx2 on ip2loc(ipend)},
		 qq{create index ip2locidx3 on ip2loc(ipstart,ipend)},
		 qq{create index ip2locidx4 on ip2loc(oct1)},
		 qq{create index ip2locidx5 on ip2loc(oct1,oct2)},
		 qq{create index ip2locidx6 on ip2loc(oct1,ipstart,ipend)},
		 qq{create index ip2locidx7 on ip2loc(oct1,oct2,ipstart,ipend)},
		 
		 qq{create virtual table ip2loc_rtree using rtree_i32 (id, x1, y1, x2, y2)}
);


my $wc = `wc -l $f`;
$wc = (split(' ', $wc))[0];

my $dbh = DBI->connect("dbi:SQLite:dbname=/opt/location-db/ip2loc.db", "", "", {AutoCommit => 0, PrintError => 1});
die DBI->errstr unless $dbh;

print "Using sqlite version " . $dbh->{sqlite_version} . "\n";

foreach my $cmd (@bootstrap) {
  print "Bootstrap: $cmd\n";
  my $rv = $dbh->do($cmd);
  die DBI->errstr . "\ncommand:\n$cmd" unless $rv;
}


my $csv = new Text::CSV({ binary  => 1 }) or die Text::CSV->error_diag();
open my $fh, $f or die "open: $!";

my $rc = 0;
$|=1;

my $rowid = 1;

print scalar localtime, " Importing..\n";
while (my $row = $csv->getline($fh)) {
  my $s = "insert into ip2loc (rowid, oct1, oct2, ipstart, ipend, shortcc, longcc, region, city, latitude, longitude) values ( $rowid, " .
    join (', ',
          ($row->[0] & 0xFF000000) >> 24,
          ($row->[0] & 0x00FF0000) >> 16,
	  $row->[0],
	  $row->[1],
	  $dbh->quote($row->[2]),
	  $dbh->quote($row->[3]),
	  $dbh->quote($row->[4]),
	  $dbh->quote($row->[5]),
	  $dbh->quote($row->[6]),
	  $dbh->quote($row->[7]),
	 ) . ")";

  my $rv = $dbh->do($s);
  die "\n\nERROR " . $dbh->errstr unless $rv;

  
  $s = "insert into ip2loc_rtree (id, x1, y1, x2, y2) values ( $rowid, " .
  	join(', ', 
  	  $row->[0],
	  $row->[0],
	  $row->[1],
	  $row->[1]
  	) . ")";
  
  $rv = $dbh->do($s);
  die "\n\nERROR: " . $dbh->errstr unless $rv;
  
  printf ("\r%2.2f%% imported. %d of %d lines.", ($rc / $wc)*100.0, $rc, $wc) if (($rc++ % 1000)==0);
  $rowid++;
}
close $fh;

print"\n",  scalar localtime , " Import finished. $rc lines imported. \n";

$dbh->commit;
$dbh->disconnect;
exit 0;
