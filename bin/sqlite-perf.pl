#/usr/bin/perl -w
use strict;

use DBI;
use Data::Dumper;
use lib '/home/jcmurphy/src/splunk/lib';
use Getopt::Std;
use UB::GeoScan;

	
my $geo = new UB::GeoScan(
	{
		locdb_cstr => 'DBI:SQLite:dbname=/opt/location-db/ip2loc.db',
		locdb_user => '',
		locdb_pass => '',
		ldap_server => 'ldap.buffalo.edu',
		ldap_binddn => 'o=University at Buffalo,c=us',
		ldap_base   => 'o=University at Buffalo,c=us',
		ldap_filter => '(userid=$ubitname)'
	}
);

my $N = 100000;
my $start = time();
for (1..$N) {
	my @a =  $geo->lookuploc("128.205.10.10");
}
my $end = time();
my $dur = $end-$start;

printf("%d sec %2.2f/sec\n", $dur, $N/$dur);
exit 0;
