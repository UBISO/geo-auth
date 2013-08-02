#!/usr/bin/perl -w
use strict;
use DBI;
use Data::Dumper;
use Net::LDAP;
use Mail::Send;

use WWW::Splunk;
use Getopt::Std;

use Try::Tiny;

BEGIN {
	# in case your splunk server uses a self signed cert
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
}



my $D      = 0;
my $mailto = 'jcmurphy@buffalo.edu';

my %opts;
getopt( 'D:hH:w:U:c:', \%opts );

help("help requested") if exists $opts{h};
help("invalid parameters") unless exists( $opts{u} ) && exists( $opts{p} );

my $cfg;
if (exists $opts{c}) {
	$cfg = new Config::Simple($opts{c});
}
else {
	$cfg = new Config::Simple("/etc/geoauth.cfg");
}

if (exists $cfg->param('libs')) {
	use lib split(/,/, $cfg->param('libs'));
}

use WWW::Splunk;
use UB::GeoScan;
use UB::AuthRecs;

if ( exists $opts{D} ) {
	print "Debugging output enabled.\n";
	$D = $opts{D};
}

try {

	my $splunk = new UB::AuthRecs(
		{
			splunkserver => $cfg->param('splunk.server'),
			username     => $cfg->param('splunk.user'),
			password     => $cfg->param('splunk.pass'),
			debug        => $opts{D}
		}
	);

	my $geo = new UB::GeoScan(
		{
			locdb_cstr  => $cfg->param('radiusdb.dbi'),
			locdb_user  => $cfg->param('radiusdb.user'),
			locdb_pass  => $cfg->param('radiusdb.pass'),
			ldap_server => $cfg->param('ldap.server'),
			ldap_binddn => $cfg->param('ldap.binddn'),
			ldap_base   => $cfg->param('ldap.base'),
			ldap_filter => $cfg->param('ldap.filter')
		}
	);

	my $numhrsago = $opts{H} || 2;
	my $sometimeago = time() - $numhrsago * 60 * 60;

	# fetch array of [username, localaddr, remoteaddr, nas, logintime, duration]

	my $byuser   = {};
	my $bycc     = {};
	my $ldapuser = {};

	print "Fetching results from Splunk..\n" if $D;

	my $srv = $splunk->fetch_smtp_logins_from_splunk( $numhrsago, $opts{U} );

	print "Correlating with location/ldap information…\n" if $D;

	for ( my $i = 0 ; $i <= $#{ $srv->{'time'} } ; $i++ ) {
		my ( $username, $remoteaddr, $smtpserver, $logintime, $logints ) = (
			$srv->{username}->[$i],   $srv->{remoteaddr}->[$i],
			$srv->{smtpserver}->[$i], $srv->{'time'}->[$i],
			$srv->{ts}->[$i]
		);

		print "Process: $username $remoteaddr $logintime\n\tLookup location.. "
		  if $D;

		my ( $cc, $reg, $city, $lat, $lon ) = $geo->lookuploc($remoteaddr);

		print "[$cc, $reg, $city, $lat, $lon]\n" if $D;

		# print join(', ', @$r, $cc, $reg, $city, $lat, $lon) . "\n" if $D;

		push @{ $byuser->{$username} }, {
			'remoteaddr'          => $remoteaddr,
			'logintimestamp'      => $logints,
			'logintime (eastern)' => $logintime,
			'country'             => $cc,
			'region'              => $reg,
			'city'                => $city,
			'lat'                 => $lat,
			'lon'                 => $lon,
			'duration' => 5    #smtp session, we just set this to 5s
		};

		print "\tLookup ldap info..\n" if $D;

		$bycc->{$cc}++;
		$ldapuser->{$username} = $geo->lookupldap($username)
		  unless exists( $ldapuser->{$username} );
	}

# now loop over each user, as long as they have >1 record,
# do a velocity measurement between each couple. if vel exceeds 600 mph, print out
# records

	my @matches = ();

	my $results     = {};
	my $userdetails = {};

	foreach my $u ( sort keys %$byuser ) {
		if ( $#{ $byuser->{$u} } > 0 ) {
			for ( my $i = 0 ; $i < $#{ $byuser->{$u} } ; $i++ ) {

				my $d = $geo->distance(
					$byuser->{$u}->[$i]->{lat},
					$byuser->{$u}->[$i]->{lon},
					$byuser->{$u}->[ $i + 1 ]->{lat},
					$byuser->{$u}->[ $i + 1 ]->{lon}
				);
				my $t =
				  $byuser->{$u}->[$i]->{logintimestamp} -
				  $byuser->{$u}->[ $i + 1 ]->{logintimestamp} +    # splunk rev sorts, so T0 > T1
				  $byuser->{$u}->[$i]->{duration};
				$t = 1 unless $t;         # no div/0
				my $v = abs( $d / ( $t / ( 60 * 60 ) ) );

				print join( ' ',
					$u,
					$byuser->{$u}->[$i]->{country},
					$byuser->{$u}->[$i]->{logintimestamp},
					$byuser->{$u}->[ $i + 1 ]->{country},
					$byuser->{$u}->[ $i + 1 ]->{logintimestamp},
					$v )
				  . "\n"
				  if $D;

				if ( $v > 600 ) {
					push @matches, $u;
					$results->{$u} .= sprintf(
						"%-20.20s %-20.20s %10.2f %6.0d %8.2f\n",

						join( '/',
							$byuser->{$u}->[$i]->{country},
							$byuser->{$u}->[$i]->{region},
							$byuser->{$u}->[$i]->{city} ),
						join( '/',
							$byuser->{$u}->[ $i + 1 ]->{country},
							$byuser->{$u}->[ $i + 1 ]->{region},
							$byuser->{$u}->[ $i + 1 ]->{city} ),
						$d, $t,
						$v
					);

					if ( !exists $userdetails->{$u} ) {
						if ( defined( $ldapuser->{$u} ) ) {
							foreach my $attr ( $ldapuser->{$u}->attributes ) {
								$userdetails->{$u} .= sprintf( "%24.24s: %s\n",
									$attr, $ldapuser->{$u}->get_value($attr) );
							}
						}
						else {
							$userdetails->{$u} = "user not in ldap?\n";
						}
					}
				}
			}
		}
	}

	if ( $#matches > -1 ) {
		my $formatted = '';
		my $numu      = scalar keys %$results;
		foreach my $u ( sort keys %$results ) {
			$formatted .= "Username: $u\n";
			$formatted .= $userdetails->{$u} . "\n";
			$formatted .= sprintf( "%-20.20s %-20.20s %12s %6s %8s\n",
				"Origin", "Destination", "Distance", "Time", "Velocity" );
			$formatted .= sprintf( "%-20.20s %-20.20s %12s %6s %8s\n",
				"(Country)", "(Country)", "(Miles)", "(Secs)", "(mph)" );

			$formatted .= "-" x 78 . "\n";
			$formatted .= $results->{$u} . "\n";
		}
		if ($D) {
			print $formatted;
		}
		else {
			sendmail( $mailto, "SMTP suspicious logins: $numu user(s)",
				$formatted );
		}
	}

	if ( exists $opts{w} ) {
		print "Outputting web pages.\n" if $D;
		webalizeit_geo_volume( $opts{w}, $bycc );
	}

}

catch {
	if ($D) {
		print "ERROR $_\n";
	}
	else {
		sendmail( $mailto, "ERROR $0", $_ );
	}
};

exit 0;

sub sendmail {
	my ( $to, $subj, $txt ) = ( shift, shift, shift );

	use Net::SMTP;
	my $smtp = Net::SMTP->new($cfg->param('smtp.server'));
	$smtp->mail( $cfg->param('smtp.from') );
	$smtp->to( $cfg->param('smtp.to') );
	$smtp->data();
	$smtp->datasend("To: $to\nSubject: $subj\n");
	$smtp->datasend("\n");
	$smtp->datasend($txt);
	$smtp->dataend();
	$smtp->quit;
}

sub help {
	my $m = shift;

	print "
$0 [-D 0-9] [-h] <-c config> <-w file> <-H hoursago>
   -c config   - default: /etc/geoauth.cfg
   -D #        - debug level default: 0
   -h          - this message
   -w dir      - output webalized information to this dir
   -H hoursago - number of hours before now to query over, default=2
   -U user     - defaults to * [remember: username is often xx\@buffalo.edu so you probably want
                 to specify eg -U joesmith\\*\n\n$m\n";
	exit 0;
}

sub webalizeit_geo_volume {
	my $dir  = shift;
	my $bycc = shift;

	die "webalize: cant write to $dir ($!)" if ( !-d $dir || !-w $dir );

	my $geopage = qq{
<html>
  <head>
    <script type='text/javascript' src='https://www.google.com/jsapi'></script>
    <script type='text/javascript'>
     google.load('visualization', '1', {'packages': ['geochart']});
     google.setOnLoadCallback(drawRegionsMap);

      function drawRegionsMap() {
        var data = google.visualization.arrayToDataTable([
         ['Country', 'Authentications'],
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
	foreach my $cc ( sort keys %$bycc ) {
		$jscode .= "['$cc', $bycc->{$cc}], ";
	}
	$geopage =~ s/%DATA%/$jscode/;
	open( FD, "> $dir/smtp.html" ) || die "cant open $dir/smtp.html";
	print FD $geopage;
	close(FD);
}
