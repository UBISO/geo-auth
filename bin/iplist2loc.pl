#!/usr/bin/perl -w
use strict;
use lib '/home/jcmurphy/src/splunk/lib';
use Carp qw(cluck croak);
use Getopt::Std;
use Try::Tiny;
use UB::GeoScan;
use Config::Simple;

my $D = 0;
$| = 1;

my %opts;
getopts('D:sx:dhpvm:c:', \%opts);
help("help requested") if exists $opts{H};

my $infile = shift;
help("file not specified") unless defined ($infile);
my $scale = 1;

if ($infile =~ /.bz2$/) {
	$scale = 6; # total fudge
	open(INF, "bunzip2 -c $infile | ") || die "cant open $infile";
}
else {
	$scale = 1;
	open(INF, $infile) || die "cant open $infile";	
}


if (exists $opts{D}) {
	print "Debugging output enabled.\n";
	$D = $opts{D};
}

if (exists $opts{v}) {
	print "Maximum verbosity.\n";
}

my %exclude_list = ();
if (exists $opts{x}) {
	foreach my $cn (split(/:/, $opts{x})) {
		$exclude_list{$cn} = 1;
	}
}



my $verbose = exists $opts{v};

try {	
	my $by_country = {};
	
	my $total_lines   = 0;
	my $skipped_lines = 0;
	my $byte_count    = 0;
	my $total_bytes   = flen($infile) * $scale; # fudge it if the file is compressed
	my $by_addr       = {};
	my $addr_vol      = {};
	
	my $prev_time = time();
	
	while (my $line = <INF>) {
		$byte_count += length($line);
		$total_lines++;
		next if ($line =~ /^seq,/);
		
		# 0    1-2    3           4          5     6     7    8     9     10   
		# seq,stime,saddr,sport,daddr,dport,dur,proto,spkts,dpkts,sbytes,dbytes
		# 93764, 12-11-14, 13:45:23, 1.0.23.48.0, 128.205.1.144.25, 0.964736, tcp, 8, 9, 2980, 873
		
		my @fields = split(/,/, $line);
		
		if (($#fields == 10) && isv4($fields[3]) && isv4($fields[4])) {
			if (exists($opts{s})) {
				my $ip = isv4($fields[3]);
				$by_addr->{$ip}++;
				$addr_vol->{$ip} += $fields[9];
			}
			else {
				my $ip = isv4($fields[4]);
				$by_addr->{$ip}++;
				$addr_vol->{$ip} += $fields[10];
			}
		}

		else {
			print "\nSkipped line: $line\n";
			$skipped_lines++;
		}
		
		if ( $verbose && (($total_lines % 5000) == 0) ) {
			printf("  %2.2f%% read  (%d kb of %d kb)           \r", 
				100*($byte_count / $total_bytes),
				$byte_count/1024, $total_bytes/1024,
				);
		}
	}

	print "\nResolving locations\n";

	$by_country = fill_in_location_info($by_addr, exists $opts{v});	
	$by_country->{':MAX'} = 0;
	$by_country->{':SUM'} = 0;
	
	foreach my $cc (keys %$by_country) {
		$by_country->{':MAX'} = ($by_country->{':MAX'} > $by_country->{$cc}) ?  $by_country->{':MAX'} : $by_country->{$cc};
		$by_country->{':SUM'} += $by_country->{$cc};
	}
	
	if (exists $opts{m}) {
		webalizeit_geo_volume($opts{m}, $by_country, exists($opts{p}));	
	}
	else {
		foreach my $cc (sort keys %$by_country) {
			printf("%35.35s %d\n", $cc, $by_country->{$cc});
		}
	}
	print "\n\nSkipped $skipped_lines out of a total of $total_lines lines\n\n";

} catch {
	croak "\n\nerror: $_";
};

exit 0;

sub isv4 {
	my $ip = shift;
	# argus is ip.ip.ip.ip.port
	return $1 if $ip =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.{0,1}/;
	return 0;
}

sub help {
	my $m = shift;
	print "
$0 [-D #] [-h] [-v] [-s|-d] [-x 'country'] [-p] [-m javascript map output file] <input file>
    -s       process src ip field
    -d       process dst ip field
    -D #     debug level
    -x country:country:...
             exclude these countries
    -p       output percentile ranks instead of raw counts
    -m file  write output to this file
    
    $m\n";
	exit 0;
}

sub flen {
	my $fn = shift;
	return (stat($fn))[7];
}

sub fill_in_location_info {
	my $byaddr = shift;
	my $verbose = shift;
	
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
	
	my $bycc = {};
	my $total_keys = scalar keys %$byaddr;
	my $key_count = 0;
	
	foreach my $ip_address (keys %$byaddr) {
		$key_count++;
		my ($country, $state, $city, $lat, $lon) = $geo->lookuploc($ip_address);
		next if !defined($country);
		if (!exists $exclude_list{$country}) {
			$bycc->{$country} += $byaddr->{$ip_address};
		}
		
		if ( $verbose && ( ($key_count % 1000) == 0) ) {
			printf("  %2.2f%% read   (%d of %d)         \r", 
				100 * ($key_count / $total_keys),
				$key_count, $total_keys);
		}
	}
	return $bycc;
}


sub webalizeit_geo_volume {
	my $fn = shift;
	my $bycc = shift;
	my $percents = shift;
	my $dir = shift;
	
    my $direction = "into";

    my $label = "Flows";
    $label = "% Flows" if $percents;
    my $title = "$label $direction UB";

	
	my $geopage = qq{
<html>
  <head>
    <script type='text/javascript' src='https://www.google.com/jsapi'></script>
    <script type='text/javascript'>
     google.load('visualization', '1', {'packages': ['geochart']});
     google.setOnLoadCallback(drawRegionsMap);

      function drawRegionsMap() {
        var data = google.visualization.arrayToDataTable([
         ['Country', '$label'],
          %DATA%
                  ]);

        var options = {};

        var chart = new google.visualization.GeoChart(document.getElementById('chart_div'));
        chart.draw(data, options);
    };
    </script>
  </head>
  <body>
    <div id="chart_div" style="width: 900px; height: 500px;"></div>
  </body>
</html>
	};

	my $jscode = '';
	foreach my $cc (sort keys %$bycc) {
		my $val = $bycc->{$cc};
		next if ($cc =~ /(bogon|rfc1918|:SUM|:MAX)/);
		$val = sprintf("%2.2f", 100*$val / $bycc->{':SUM'}) if ($percents);
		$cc =~ s/\'//g;
		$jscode .= "['$cc', $val], \n";
	}
	$geopage =~ s/%DATA%/$jscode/;
	open (FD, "> $fn") || die "cant open $fn";
	print FD $geopage;
	close(FD);
}

sub make_rate {
	my $cur_time = shift;
	my $cur_count = shift;
	return sub { 
		my $new_count = shift; 
		my $rate = ($new_count - $cur_count) / (time() - $cur_time);
		$cur_time = time();
		$cur_count = $new_count;
		return $rate;
	}
}